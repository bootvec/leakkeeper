"""QUIC / UDP-443 check — does UDP (QUIC) route through the tunnel?

Three independent signals:
  1. STUN-mapped UDP egress vs. HTTP egress (does UDP leave via the tunnel?).
  2. A real QUIC probe: a long-header Initial packet carrying an unsupported
     version. A genuine QUIC server MUST answer with a Version Negotiation
     packet, so any reply proves UDP/443 reaches a QUIC endpoint.
  3. The QUIC probe outcome cross-referenced with (1).
"""

from __future__ import annotations

import os
import socket
import struct

from ..config import CheckContext
from ..netutil import http_get_text, ip_version, parallel_map, stun_mapped_address
from ..result import CheckResult, Status

# Real QUIC endpoints (resolved to IPv4 at run time).
QUIC_HOSTS = ["www.google.com", "cloudflare.com", "www.cloudflare.com"]


def quic_probe(host: str, port: int = 443, timeout: int = 5) -> str:
    """Send a QUIC Initial with an unsupported version; expect Version Negotiation.

    Returns 'reachable' (got a reply), 'timeout' (filtered/unreachable) or 'error'.
    """
    dcid = os.urandom(8)
    scid = os.urandom(8)
    # long header (0xC0), unsupported draft version 0xff00001d, DCID + SCID
    pkt = (
        b"\xc0"
        + struct.pack(">I", 0xFF00001D)
        + bytes([len(dcid)]) + dcid
        + bytes([len(scid)]) + scid
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (host, port))
        data, _addr = sock.recvfrom(2048)
        if _is_version_negotiation(data, dcid, scid):
            return "reachable"
        return "invalid-response"
    except socket.timeout:
        return "timeout"
    except OSError:
        return "error"
    finally:
        sock.close()


def _is_version_negotiation(data: bytes, dcid: bytes, scid: bytes) -> bool:
    if len(data) < 7 or not (data[0] & 0x80) or (data[0] & 0x30):
        return False
    if data[1:5] != b"\x00\x00\x00\x00":
        return False
    dlen = data[5]
    if 6 + dlen >= len(data):
        return False
    response_dcid = data[6 : 6 + dlen]
    slen_offset = 6 + dlen
    slen = data[slen_offset]
    if slen_offset + 1 + slen > len(data):
        return False
    version_bytes = data[slen_offset + 1 + slen :]
    return (
        response_dcid == scid
        and data[slen_offset + 1 : slen_offset + 1 + slen] == dcid
        and len(version_bytes) >= 4
        and len(version_bytes) % 4 == 0
    )


def _resolve_ipv4(host: str) -> list[str]:
    addresses: list[str] = []
    try:
        for info in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_DGRAM):
            if info[4][0] not in addresses:
                addresses.append(info[4][0])
    except OSError:
        pass
    return addresses


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(id="quic", name="QUIC (UDP 443)", category="udp")
    evidence: list[str] = []

    udp_ip, _port, method = stun_mapped_address("stun.l.google.com", 19302, ctx.timeout)
    if udp_ip:
        evidence.append(f"UDP egress (STUN): {udp_ip} ({method})")

    http_ip = http_get_text("https://api.ipify.org", ctx.timeout)
    evidence.append(f"HTTP egress: {http_ip or '(unknown)'}")

    resolved_raw = {host: _resolve_ipv4(host) for host in QUIC_HOSTS}
    resolved = {
        host: (value if isinstance(value, list) else ([value] if value else []))
        for host, value in resolved_raw.items()
    }
    for host, ips in resolved.items():
        if not ips:
            evidence.append(f"QUIC {host}:443 -> (unresolvable)")

    probes = [(host, ip) for host, ips in resolved.items() for ip in ips]
    probe_results = parallel_map(
        lambda item: quic_probe(item[1], 443, ctx.timeout), probes
    )
    outcomes = {}
    for host in QUIC_HOSTS:
        outcomes[host] = (
            [{"ip": "", "result": "unresolvable"}] if not resolved[host] else []
        )
    for (host, ip), outcome in zip(probes, probe_results):
        outcomes[host].append({"ip": ip, "result": outcome})
        evidence.append(f"QUIC {host} ({ip}):443 -> {outcome}")

    any_reachable = any(
        probe["result"] == "reachable"
        for probes_for_host in outcomes.values()
        for probe in probes_for_host
    )

    details = {
        "udp_egress": udp_ip,
        "http_egress": http_ip,
        "quic_probes": outcomes,
    }

    # The reliable signal is the STUN UDP egress vs. the HTTP egress: QUIC runs
    # over UDP, so if UDP leaves via the tunnel, QUIC cannot bypass it. The raw
    # QUIC probe is only supplementary (a "timeout" there is ambiguous — QUIC
    # servers silently drop garbage), so it never drives the verdict on its own.
    # Only compare same-family addresses (IPv4 UDP vs IPv4 HTTP): a cross-family
    # result is dual-stack, not a leak.
    same_family = (
        udp_ip and http_ip and ip_version(udp_ip) == ip_version(http_ip)
    )
    if same_family and udp_ip != http_ip:
        res.status = Status.FAIL
        res.summary = (
            f"UDP egress {udp_ip} differs from HTTP egress {http_ip} — "
            "QUIC/UDP traffic bypasses the tunnel"
        )
    elif same_family and udp_ip == http_ip:
        res.status = Status.PASS
        res.summary = (
            f"UDP egress {udp_ip} matches HTTP egress — QUIC/UDP is tunneled"
        )
    elif any_reachable:
        res.status = Status.WARN
        res.summary = "QUIC (UDP 443) reachable but UDP egress could not be confirmed"
    else:
        res.status = Status.WARN
        res.summary = "could not confirm UDP routing (STUN failed, QUIC probe inconclusive)"

    res.evidence = evidence
    res.details = details
    return res
