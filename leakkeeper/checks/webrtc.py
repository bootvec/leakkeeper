"""WebRTC / UDP leak check — STUN-mapped address vs. HTTP egress."""

from __future__ import annotations

from ..config import CheckContext
from ..netutil import (
    http_get_text,
    ip_version,
    is_private_or_local,
    parallel_map,
    stun_mapped_address,
)
from ..result import CheckResult, Status

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(id="webrtc", name="WebRTC / UDP (STUN)", category="udp")
    evidence: list[str] = []
    mapped_ips: list[str] = []

    results = parallel_map(
        lambda srv: stun_mapped_address(srv[0], srv[1], ctx.timeout), STUN_SERVERS
    )
    for (server, _port), (ip, _p, method) in zip(STUN_SERVERS, results):
        if ip:
            evidence.append(f"STUN {server} -> {ip} ({method})")
            if ip not in mapped_ips:
                mapped_ips.append(ip)
        else:
            evidence.append(f"STUN {server} -> (no response)")

    http_ip = http_get_text("https://api.ipify.org", ctx.timeout)

    public_mapped = [ip for ip in mapped_ips if not is_private_or_local(ip)]

    details = {"stun_mapped": mapped_ips, "http_ipv4": http_ip, "public_mapped": public_mapped}

    issues: list[str] = []

    if not mapped_ips:
        res.status = Status.ERROR
        res.summary = "no STUN server answered (UDP may be blocked)"
        res.evidence = evidence
        res.details = details
        return res

    distinct_public = set(public_mapped)

    # Multiple distinct *same-family* public UDP egress addresses => split/leak
    # signal. One IPv4 plus one IPv6 is normal dual-stack, not a leak.
    v4 = sorted(a for a in distinct_public if ip_version(a) == 4)
    v6 = sorted(a for a in distinct_public if ip_version(a) == 6)
    if len(v4) > 1 or len(v6) > 1:
        issues.append(
            f"multiple distinct UDP egress addresses observed: {sorted(distinct_public)}"
        )

    # UDP reveals a different public IP than TCP/HTTP *within the same family* =>
    # UDP bypasses the tunnel. A cross-family result (IPv4 vs IPv6) is dual-stack
    # and not itself a leak.
    http_fam = ip_version(http_ip) if http_ip else None
    same_fam = sorted(a for a in distinct_public if ip_version(a) == http_fam)
    if http_ip and same_fam and http_ip not in same_fam:
        issues.append(
            f"UDP egress {same_fam} differs from HTTP egress {http_ip} "
            "— UDP traffic bypasses the tunnel"
        )

    # UDP reveals a private address => no direct public exposure via UDP.
    if not public_mapped:
        res.status = Status.WARN
        res.summary = (
            f"UDP egress is private ({mapped_ips[0]}) — NAT'ed, cannot confirm "
            "whether UDP is tunneled"
        )
    elif not http_ip:
        res.status = Status.WARN
        res.summary = (
            f"UDP egress {public_mapped} was observed, but HTTP egress could not "
            "be determined — routing consistency is unknown"
        )
    elif issues:
        res.status = Status.FAIL
        res.summary = "; ".join(issues)
    else:
        res.status = Status.PASS
        res.summary = (
            f"UDP egress {public_mapped[0]} consistent"
            + (f" with HTTP egress {http_ip}" if http_ip else "")
        )

    res.evidence = evidence
    res.details = details
    return res
