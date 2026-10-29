"""EDNS Client Subnet (ECS) leak check — does the resolver disclose/forward a subnet?

Two probes are compared:
  1. *baseline* — a normal TXT query to Google's ``o-o.myaddr.l.google.com``
     reflector; the value it returns is what the resolver presents (its own IP
     or subnet when no ECS is added).
  2. *active* — the same query with an explicit ECS option carrying our own
     egress /24, to detect whether the resolver forwards ECS at all.

Verdict logic is *resolver-aware*, which removes the old /16-vs-egress blind
spot:

  * A baseline disclosure is normal if it belongs to the **resolver's own**
    network (or the tunnel egress). It is suspicious — i.e. a possible real
    client-subnet leak — only if it matches neither.
  * A resolver that echoes back the ECS subnet we injected is *forwarding ECS*,
    which could leak a real client subnet if a client supplied one.
"""

from __future__ import annotations

from ..config import CheckContext
from ..netutil import (
    asn_lookup,
    dns_query,
    http_get_text,
    ip_version,
    is_private_or_local,
    resolver_ips,
    same_subnet,
    system_nameservers,
)
from ..result import CheckResult, Status

GOOGLE_REFLECTOR = "o-o.myaddr.l.google.com"


def _extract(recs: list[dict]) -> list[str]:
    """Pull the first real IP/subnet out of a reflector TXT value.

    Google's ``o-o.myaddr.l.google.com`` returns either a bare IP (no ECS) or a
    ``edns0-client-subnet a.b.c.d/24`` line (ECS present). We scan every
    whitespace token, strip an optional ``/prefix``, and keep the first one that
    actually parses as an IP address, so the literal ``edns0-client-subnet``
    label is never mistaken for an address.
    """
    out: list[str] = []
    for rec in recs:
        val = rec.get("value", "")
        if not val:
            continue
        for token in val.split():
            candidate = token.split("/")[0]
            if candidate and ip_version(candidate) and not is_private_or_local(candidate):
                out.append(candidate)
                break
    return out


def _has_ecs(recs: list[dict]) -> bool:
    """True if the reflector answer contains an ECS line (not just its own IP).

    Google returns ``edns0-client-subnet a.b.c.d/24`` only when an ECS option
    reached it; a bare address means no ECS was forwarded.
    """
    return any("edns0-client-subnet" in str(rec.get("value", "")).lower() for rec in recs)


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(id="ecs", name="EDNS Client Subnet (ECS)", category="dns")
    evidence: list[str] = []

    egress = http_get_text("https://api.ipify.org", ctx.timeout) or ""
    servers = system_nameservers()

    if not servers:
        res.status = Status.SKIP
        res.summary = "no nameservers configured — cannot probe ECS reflection"
        res.evidence = ["resolv.conf nameservers: (none)"]
        res.details = {"baseline": [], "active": [], "egress": egress}
        return res

    resolvers = [r for r in resolver_ips(ctx.timeout) if not is_private_or_local(r)]
    for r in resolvers:
        evidence.append(f"recursive resolver: {r}")

    # Ownership by ASN (fallback to /24) — the disclosed subnet may legitimately
    # come from another /24 of the resolver's or the egress provider's network.
    egress_asn = asn_lookup(egress, ctx.timeout) if egress else None
    resolver_asns = {r: asn_lookup(r, ctx.timeout) for r in resolvers}

    baseline: list[str] = []
    active: list[str] = []
    baseline_ecs = False

    for server in servers:
        # baseline: no ECS
        base_recs = dns_query(GOOGLE_REFLECTOR, 16, server, timeout=ctx.timeout)
        base = _extract(base_recs)
        baseline_ecs = baseline_ecs or _has_ecs(base_recs)
        baseline.extend(base)
        for v in base:
            evidence.append(f"resolver {server} baseline TXT: {v}")

        # active: inject ECS carrying our egress /24
        if egress:
            act_recs = dns_query(
                GOOGLE_REFLECTOR, 16, server, timeout=ctx.timeout, ecs=egress
            )
            act = _extract(act_recs)
            active.extend(act)
            for v in act:
                evidence.append(f"resolver {server} active (ECS={egress}) TXT: {v}")

    baseline = list(dict.fromkeys(baseline))
    active = list(dict.fromkeys(active))
    disclosed = baseline + active

    # A baseline disclosure is normal if it belongs to the resolver's own
    # provider or to the tunnel egress provider. Ownership is checked by origin
    # ASN first, falling back to /24, so a same-/16-but-other-provider subnet is
    # still flagged and same-provider geo-distributed blocks are not.
    def belongs_to(disclosed: str, ip: str, asn: int | None) -> bool:
        if asn is not None:
            disclosed_asn = asn_lookup(disclosed, ctx.timeout)
            if disclosed_asn is not None:
                return disclosed_asn == asn
        return same_subnet(disclosed, ip)

    suspicious: list[str] = []
    for d in baseline:
        matches_resolver = any(
            belongs_to(d, r, resolver_asns.get(r)) for r in resolvers
        )
        matches_egress = bool(egress) and belongs_to(d, egress, egress_asn)
        if not matches_resolver and not matches_egress:
            suspicious.append(d)

    # Forwarding is only proven by an ECS line in the answer, or by a value in
    # the active probe that the baseline did not already return. Comparing the
    # active value's /24 to the egress alone is not enough: when resolver and
    # egress share a /24, the resolver's own (bare) IP would be mistaken for an
    # echoed ECS and produce a false positive.
    new_active = [a for a in active if a not in baseline]
    forwards_ecs = baseline_ecs or (
        bool(egress) and any(same_subnet(a, egress) for a in new_active)
    )

    details = {
        "baseline": baseline,
        "active": active,
        "egress": egress,
        "egress_asn": egress_asn,
        "resolvers": resolvers,
        "resolver_asns": resolver_asns,
        "suspicious_baseline": suspicious,
        "baseline_ecs": baseline_ecs,
        "forwards_ecs": forwards_ecs,
    }

    if not disclosed:
        res.status = Status.SKIP
        res.summary = "could not query ECS reflector (no DNS answer)"
    elif suspicious:
        res.status = Status.WARN
        res.summary = (
            f"resolver disclosed subnet(s) {suspicious} matching neither its own network "
            f"nor the tunnel egress {egress} — possible real-subnet leak"
        )
    elif forwards_ecs:
        res.status = Status.WARN
        res.summary = (
            "resolver forwards EDNS Client Subnet — a misconfigured upstream "
            "could leak your real subnet"
        )
    else:
        res.status = Status.PASS
        res.summary = (
            f"no ECS disclosure outside the resolver/tunnel networks ({disclosed[0]})"
        )

    res.evidence = evidence
    res.details = details
    return res
