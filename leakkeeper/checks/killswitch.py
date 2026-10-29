"""Kill-switch check — would traffic escape the tunnel if it dropped?"""

from __future__ import annotations

import re
import shutil

from ..config import CheckContext
from ..result import CheckResult, Status
from ._shared import is_tunnel_dev, run_json, run_json_result
from ._shared import run as run_cmd


def _default_routes_in(table: str, v6: bool) -> tuple[bool, list[tuple[str, str]]]:
    """Return [(device, gateway)] for default routes in a routing table."""
    ok, routes = run_json_result(
        ["ip", "-j", "-6" if v6 else "-4", "route", "show", "table", table]
    )
    out: list[tuple[str, str]] = []
    for r in routes:
        if r.get("dst") != "default":
            continue
        out.append((r.get("dev", "?"), r.get("gateway", "")))
    return ok, out


def _all_default_routes(v6: bool) -> tuple[bool, list[tuple[str, str, str]]]:
    """Return [(table, device, gateway)] for default routes across all tables."""
    ok, routes = run_json_result(
        ["ip", "-j", "-6" if v6 else "-4", "route", "show", "table", "all"]
    )
    out: list[tuple[str, str, str]] = []
    for r in routes:
        if r.get("dst") != "default":
            continue
        out.append((r.get("table", "main"), r.get("dev", "?"), r.get("gateway", "")))
    return ok, out


def _iptables_output() -> list[str]:
    """OUTPUT-chain policy and egress DROP/REJECT rules from iptables."""
    lines: list[str] = []
    if not shutil.which("iptables"):
        return lines
    rc, policy = run_cmd(["iptables", "-S", "OUTPUT"])
    if rc != 0:
        return lines
    lines.append(f"OUTPUT policy: {policy.splitlines()[0] if policy.splitlines() else 'unknown'}")
    for ln in policy.splitlines():
        low = ln.lower()
        # General egress drop/reject that is not the SSH keep-alive exception.
        is_drop = "-j drop" in low or "-j reject" in low
        ssh_only = re.search(r"--?(?:dports?|sports?)\s+22(?:\s|$)", low)
        if is_drop and not ssh_only:
            lines.append(f"egress rule: {ln.strip()}")
    return lines


def _nft_output() -> list[str]:
    """OUTPUT-chain policy and egress DROP/REJECT rules from nftables (JSON).

    Uses ``nft -j`` so the parse is stable across nftables versions and locale.
    """
    lines: list[str] = []
    if not shutil.which("nft"):
        return lines
    data = run_json(["nft", "-j", "list", "ruleset"])
    if not data or not isinstance(data, dict):
        return lines

    # Two distinct kill-switch signals in nftables:
    #   1. a filter OUTPUT chain whose *policy* is drop/reject, or
    #   2. a rule in a filter OUTPUT chain whose verdict is drop/reject
    #      (e.g. a counter+drop at the end of an accept-policy chain).
    filter_output = set()
    for entry in data.get("nftables", []):
        chain = entry.get("chain")
        if chain and chain.get("hook") == "output" and chain.get("type") == "filter":
            policy = (chain.get("policy") or "").lower()
            if policy in ("drop", "reject"):
                lines.append(f"OUTPUT policy: -P OUTPUT {policy.upper()}")
            filter_output.add(chain["name"])

    for entry in data.get("nftables", []):
        rule = entry.get("rule")
        if not rule or rule.get("chain") not in filter_output:
            continue
        # A rule is a kill-switch signal if it ends in an unconditional drop or
        # reject verdict (a counter+drop, or log+drop). Skip the SSH keep-alive
        # exception (dport/sport 22).
        if not _rule_verdicts_drop(rule):
            continue
        if _rule_matches_port_22(rule):
            continue
        lines.append(f"egress rule: {rule.get('family')} {rule.get('table')} #{rule.get('handle')}")

    return lines


def _rule_verdicts_drop(rule: dict) -> bool:
    """True if a nft rule's terminal verdict is drop/reject.

    A rule can contain intermediate verdict-like expressions in a nested
    conditional statement. Only the terminal verdict proves that the rule
    actually blocks matching egress.
    """
    exprs = rule.get("expr") or []
    for expr in reversed(exprs):
        verdict = expr.get("verdict") if isinstance(expr, dict) else None
        kind = verdict.get("kind") if isinstance(verdict, dict) else None
        if "drop" in expr or "reject" in expr or kind in ("drop", "reject"):
            return True
        if kind in ("accept", "continue", "jump", "return") or any(
            key in expr for key in ("accept", "continue", "jump", "return")
        ):
            return False
    return False


def _rule_matches_port_22(rule: dict) -> bool:
    """True if the rule matches tcp port 22 (the SSH keep-alive exception)."""
    for expr in rule.get("expr") or []:
        match = expr.get("match")
        if not match:
            continue
        left = match.get("left") or {}
        payload = left.get("payload") or {}
        right = match.get("right")
        if payload.get("field") in ("dport", "sport") and str(right) == "22":
            return True
    return False


def _output_firewall() -> list[str]:
    """Return OUTPUT-chain policy and egress DROP/REJECT rules (kill-switch signals)."""
    return _iptables_output() + _nft_output()


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(id="killswitch", name="Kill-switch", category="routing")
    evidence: list[str] = []

    rules_ok, rules = run_json_result(["ip", "-j", "rule", "show"])
    evidence.append("[ip rule]")
    for r in rules:
        evidence.append(f"  {r.get('priority')}: {r.get('src')} lookup {r.get('table')}")

    routes_v4_ok, routes_v4 = _all_default_routes(False)
    routes_v6_ok, routes_v6 = _all_default_routes(True)
    all_routes = routes_v4 + routes_v6
    evidence.append("[default routes (all tables)]")
    for table, dev, gw in all_routes:
        evidence.append(f"  table {table}: via {gw} dev {dev}")

    fw = _output_firewall()
    if fw:
        evidence.append("[firewall OUTPUT]")
        evidence.extend(f"  {line}" for line in fw)

    # Fallback analysis: a default route in the MAIN table via a physical device
    # means traffic can escape if the tunnel (policy-routed) disappears.
    main_v4_ok, main_v4 = _default_routes_in("main", False)
    main_v6_ok, main_v6 = _default_routes_in("main", True)
    main_defaults = main_v4 + main_v6
    phys_fallback = [(d, g) for (d, g) in main_defaults if not is_tunnel_dev(d)]

    tunnel_defaults = [(t, d, g) for (t, d, g) in all_routes if is_tunnel_dev(d)]

    # A real kill-switch either drops egress by policy or with an explicit rule.
    output_drop = any(
        "policy" in line and ("drop" in line.lower() or "reject" in line.lower())
        for line in fw
    ) or any(line.startswith("egress rule") for line in fw)

    details = {
        "ip_rule": [f"{r.get('priority')}: {r.get('src')} lookup {r.get('table')}" for r in rules],
        "default_routes": [{"table": t, "dev": d, "gw": g} for t, d, g in all_routes],
        "physical_fallback": [{"dev": d, "gw": g} for d, g in phys_fallback],
        "output_drop": output_drop,
        "firewall": fw,
        "command_status": {
            "ip_rule": rules_ok,
            "ipv4_routes": routes_v4_ok,
            "ipv6_routes": routes_v6_ok,
            "ipv4_main": main_v4_ok,
            "ipv6_main": main_v6_ok,
        },
    }

    if not all((rules_ok, routes_v4_ok, routes_v6_ok, main_v4_ok, main_v6_ok)):
        failed = [
            name for name, ok in details["command_status"].items() if not ok
        ]
        res.status = Status.ERROR
        res.summary = f"could not read routing state: {', '.join(failed)}"
    elif phys_fallback and not output_drop:
        devs = ", ".join(d for d, _ in phys_fallback)
        res.status = Status.FAIL
        res.summary = (
            f"no kill-switch: default route via physical device '{devs}' in main table "
            "and no egress DROP rule — a tunnel drop would leak traffic"
        )
    elif not tunnel_defaults and not phys_fallback:
        res.status = Status.WARN
        res.summary = "no default route found at all (unexpected state)"
    else:
        res.status = Status.PASS
        res.summary = (
            f"kill-switch effective: "
            f"tunnel default via {[d for _, d, _ in tunnel_defaults]}"
            + (", egress DROP present" if output_drop else "")
        )

    res.evidence = evidence
    res.details = details
    return res
