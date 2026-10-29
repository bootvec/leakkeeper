"""IP leak check — IPv4/IPv6 egress consistency vs. the tunnel."""

from __future__ import annotations

from ..config import CheckContext
from ..netutil import (
    http_get_json,
    http_get_text,
    ip_version,
    is_private_or_local,
    parallel_map,
)
from ..result import CheckResult, Status
from ._shared import run_json

IPV4_ENDPOINTS = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip",
    "https://icanhazip.com",
]

# IPv6-only hostnames (AAAA records only). Responses are validated to be real
# IPv6 literals before they are trusted.
IPV6_ENDPOINTS = [
    "https://v6.ident.me",
    "https://ipv6.icanhazip.com",
]


def _global_ipv6_addresses() -> list[str]:
    """Return global-scope IPv6 addresses configured on the host."""
    addrs: list[str] = []
    for iface in run_json(["ip", "-j", "-6", "addr", "show"]):
        for info in iface.get("addr_info", []):
            local = info.get("local")
            if local and info.get("scope") == "global" and ip_version(local) == 6:
                addrs.append(local)
    return addrs


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(
        id="ip",
        name="IP leak (IPv4 / IPv6)",
        category="identity",
    )
    evidence: list[str] = []
    details = {"ipv4": {}, "ipv6": {}, "global_ipv6": []}

    # --- IPv4 egress ---
    ipv4_map = {}
    v4_results = parallel_map(
        lambda url: http_get_text(url, ctx.timeout), IPV4_ENDPOINTS
    )
    for url, text in zip(IPV4_ENDPOINTS, v4_results):
        if text:
            candidate = text.strip().split()[0]
            if ip_version(candidate) == 4:  # only trust real IPv4 literals
                ipv4_map[url] = candidate
    for url, ip in ipv4_map.items():
        evidence.append(f"[IPv4] {url} -> {ip}")

    # --- IPv6 egress (validated) ---
    ipv6_map = {}
    v6_results = parallel_map(
        lambda url: http_get_text(url, ctx.timeout), IPV6_ENDPOINTS
    )
    for url, text in zip(IPV6_ENDPOINTS, v6_results):
        if text:
            candidate = text.strip().split()[0]
            if ip_version(candidate) == 6:  # only trust real IPv6 literals
                ipv6_map[url] = candidate
    for url, ip in ipv6_map.items():
        evidence.append(f"[IPv6] {url} -> {ip}")

    # --- Host's own global IPv6 (a proxy for "could IPv6 bypass the tunnel") ---
    global_v6 = _global_ipv6_addresses()
    if global_v6:
        evidence.append(f"[host] global IPv6 address(es): {global_v6}")

    # --- Mullvad confirmation ---
    mullvad = http_get_json("https://am.i.mullvad.net/json", ctx.timeout)
    is_mullvad = None
    if mullvad:
        flag = mullvad.get("mullvad_exit_ip")
        if flag is True or flag is False:
            is_mullvad = flag
        evidence.append(
            f"[Mullvad] ip={mullvad.get('ip')} exit={is_mullvad} "
            f"country={mullvad.get('country')} server={mullvad.get('mullvad_server_type')}"
        )

    details["ipv4"] = ipv4_map
    details["ipv6"] = ipv6_map
    details["global_ipv6"] = global_v6

    ipv4 = list(dict.fromkeys(ipv4_map.values()))
    ipv6 = list(dict.fromkeys(ipv6_map.values()))
    public_v4 = [ip for ip in ipv4 if not is_private_or_local(ip)]
    public_v6 = [ip for ip in ipv6 if not is_private_or_local(ip)]
    details["public_ipv4"] = public_v4
    details["public_ipv6"] = public_v6

    issues: list[str] = []
    warnings: list[str] = []

    # 1. Multiple distinct IPv4 egress addresses => split/leak signal
    if len(set(public_v4)) > 1:
        issues.append(
            f"multiple distinct IPv4 egress addresses observed: {sorted(set(public_v4))}"
        )

    # 2. Expected IP mismatch (compare same-family expectations).
    #    --expect-ip is family-agnostic; --expect-ip6 is IPv6-only.
    expect_v4 = ctx.expect_ip if (ctx.expect_ip and ip_version(ctx.expect_ip) == 4) else None
    expect_v6 = (
        ctx.expect_ip6
        or (ctx.expect_ip if (ctx.expect_ip and ip_version(ctx.expect_ip) == 6) else None)
    )
    if expect_v4 and public_v4 and expect_v4 not in public_v4:
        issues.append(f"IPv4 egress {public_v4} does not match expected {expect_v4}")
    if expect_v6 and public_v6 and expect_v6 not in public_v6:
        issues.append(f"IPv6 egress {public_v6} does not match expected {expect_v6}")

    # 3. IPv6 leak: confirmed IPv6 egress is a failure unless it matches an
    #    expected IPv6; a bare global IPv6 (no confirmed egress) is a warning.
    if public_v6:
        if expect_v6 and expect_v6 in public_v6:
            pass  # expected IPv6 egress confirmed
        else:
            issues.append(f"public IPv6 reachable: {public_v6} — IPv6 may bypass the tunnel")
    elif global_v6:
        warnings.append(
            f"host has global IPv6 {global_v6} but no IPv6 tunnel detected — "
            "IPv6 traffic may bypass the tunnel"
        )

    # 4. Mullvad confirmation — only a hard failure when the operator explicitly
    #    expects a Mullvad exit (--expect-mullvad). For any other VPN the
    #    "mullvad_exit_ip=false" answer is expected and merely informational.
    if ctx.expect_mullvad and is_mullvad is False:
        issues.append("am.i.mullvad.net reports mullvad_exit_ip=false (expected Mullvad exit)")
    elif ctx.expect_mullvad and is_mullvad is True:
        details["mullvad_confirmed"] = True

    if issues:
        res.status = Status.FAIL
        res.summary = "; ".join(issues)
    elif not public_v4:
        res.status = Status.ERROR
        res.summary = "could not determine public IPv4 egress (no endpoint answered)"
    elif warnings:
        res.status = Status.WARN
        res.summary = "; ".join(warnings)
    else:
        res.status = Status.PASS
        res.summary = (
            f"IPv4 egress consistent ({public_v4[0]})"
            + (f"; IPv6 egress {public_v6[0]}" if public_v6 else "; no IPv6 connectivity")
        )

    res.evidence = evidence
    res.details = details
    return res
