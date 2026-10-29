"""DNS leak check — resolver path and actual recursive resolver discovery."""

from __future__ import annotations

from ..config import CheckContext
from ..netutil import (
    asn_lookup,
    dns_query,
    http_get_text,
    is_private_or_local,
    neighborhood,
    resolve_a,
    same_subnet,
    system_nameservers,
)
from ..result import CheckResult, Status

# "whoami" names: the A record returned is the recursive resolver's own IP.
WHOAMI_NAMES = [
    "whoami.akamai.net",
    "whoami.ultradns.net",
]

# Well-known third-party public resolvers. If the actual resolver is one of these
# (and not the tunnel egress' own resolver), DNS is leaving to a third party —
# a much stronger leak signal than an IP-neighbourhood guess.
KNOWN_PUBLIC_RESOLVERS = {
    "8.8.8.8", "8.8.4.4",                       # Google
    "1.1.1.1", "1.0.0.1",                       # Cloudflare
    "9.9.9.9", "149.112.112.112",               # Quad9
    "208.67.222.222", "208.67.220.220",         # OpenDNS
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4",  # Level3
    "64.6.64.6", "64.6.65.6",                   # Verisign
    "77.88.8.8", "77.88.8.1",                   # Yandex
}


def _resolver_ips(ctx: CheckContext) -> list[str]:
    """Actual public recursive resolvers, discovered via whoami names."""
    found: list[str] = []
    for name in WHOAMI_NAMES:
        for ip in resolve_a(name, ctx.timeout):
            if ip not in found:
                found.append(ip)
    return found


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(id="dns", name="DNS leak", category="dns")
    evidence: list[str] = []

    servers = system_nameservers()
    evidence.append(f"resolv.conf nameservers: {servers or '(none)'}")

    private_ns = [s for s in servers if is_private_or_local(s)]
    public_ns = [s for s in servers if not is_private_or_local(s)]

    resolvers = _resolver_ips(ctx)
    public_resolvers = [r for r in resolvers if not is_private_or_local(r)]
    for r in resolvers:
        evidence.append(f"recursive resolver: {r}")

    # Also ask Google's reflector via a direct query when no whoami answered
    if not resolvers and servers:
        for server in servers[:2]:
            recs = dns_query("o-o.myaddr.l.google.com", 16, server, timeout=ctx.timeout)
            for rec in recs:
                if rec.get("value"):
                    evidence.append(f"google reflector @{server}: {rec['value']}")

    details = {
        "nameservers": servers,
        "private_nameservers": private_ns,
        "public_nameservers": public_ns,
        "resolvers": resolvers,
        "public_resolvers": public_resolvers,
    }

    issues: list[str] = []

    # Primary signal: a public resolver configured in resolv.conf bypasses tunnel DNS.
    if public_ns:
        issues.append(
            f"resolv.conf points to public DNS ({', '.join(public_ns)}) "
            "instead of the tunnel DNS"
        )

    # Private DNS is normally expected (tunnel-local resolver), but it can be
    # disallowed via allow_private_dns for strict setups.
    if private_ns and not ctx.allow_private_dns:
        issues.append(
            f"resolv.conf uses private DNS ({', '.join(private_ns)}) "
            "but allow_private_dns is disabled"
        )

    # Identify resolver ownership by origin ASN when possible (Team Cymru DNS),
    # falling back to /24 proximity only when the lookup is unavailable. This is
    # what makes "same provider" correct: providers can share a /16, and one
    # provider can span many /16s.
    egress = http_get_text("https://api.ipify.org", ctx.timeout) or ""
    egress_asn = asn_lookup(egress, ctx.timeout) if egress else None
    resolver_asns = {r: asn_lookup(r, ctx.timeout) for r in public_resolvers}

    def same_owner(resolver: str) -> bool:
        if egress_asn is not None:
            resolver_asn = resolver_asns.get(resolver)
            if resolver_asn is not None:
                return resolver_asn == egress_asn
        return bool(egress) and same_subnet(resolver, egress)

    off_provider = [r for r in public_resolvers if not same_owner(r)]

    # Multiple distinct providers => requests are leaking out. Group by ASN when
    # known so two different providers inside one /16 are still caught.
    def owner_key(r: str) -> tuple:
        asn = resolver_asns.get(r)
        return ("asn", asn) if asn is not None else ("net", neighborhood(r))

    distinct = {owner_key(r) for r in public_resolvers}
    if len(distinct) > 1:
        issues.append(
            f"multiple distinct recursive resolvers observed: {sorted(set(public_resolvers))}"
        )

    # Expected resolver mismatch
    if ctx.expect_dns and public_resolvers and not any(
        r in ctx.expect_dns for r in public_resolvers
    ):
        issues.append(
            f"resolver {public_resolvers} not in expected {ctx.expect_dns}"
        )

    # Well-known third-party DNS is a leak unless it belongs to the egress
    # provider itself (e.g. Cloudflare WARP: 1.1.1.1 and the egress are both
    # AS13335, so that is the tunnel's own resolver, not a leak).
    third_party = [
        r for r in public_resolvers
        if r in KNOWN_PUBLIC_RESOLVERS and not same_owner(r)
    ]
    if third_party:
        issues.append(
            f"DNS queries are answered by a third-party public resolver "
            f"{third_party} — your DNS is not going through the VPN"
        )

    same_provider = bool(public_resolvers) and not off_provider
    details["egress_ip"] = egress
    details["egress_asn"] = egress_asn
    details["resolver_asns"] = resolver_asns
    details["off_provider_resolvers"] = off_provider
    details["same_provider_resolver"] = same_provider
    details["third_party_resolvers"] = third_party

    if issues:
        res.status = Status.FAIL
        res.summary = "; ".join(issues)
    elif not resolvers:
        res.status = Status.ERROR
        res.summary = "could not determine the recursive DNS resolver"
    elif off_provider:
        res.status = Status.WARN
        res.summary = (
            f"resolver(s) {off_provider} are public and not in the egress "
            f"provider (ASN {egress_asn if egress_asn is not None else 'n/a'}) "
            "— verify they belong to the VPN, not the local ISP"
        )
    else:
        res.status = Status.PASS
        res.summary = (
            f"DNS uses tunnel/private resolver(s): "
            f"{', '.join(private_ns) or public_resolvers or resolvers}"
        )

    res.evidence = evidence
    res.details = details
    return res
