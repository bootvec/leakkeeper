"""Check registry — maps a check id to its module."""

from __future__ import annotations

from . import (
    dns,
    ecs,
    interface,
    ip,
    killswitch,
    mdns,
    quic,
    splittunnel,
    tcptimestamp,
    webrtc,
    webrtclocal,
)

CHECKS: dict[str, object] = {
    "ip": ip,
    "dns": dns,
    "webrtc": webrtc,
    "webrtclocal": webrtclocal,
    "quic": quic,
    "ecs": ecs,
    "killswitch": killswitch,
    "splittunnel": splittunnel,
    "mdns": mdns,
    "interface": interface,
    "tcptimestamp": tcptimestamp,
}

ORDER: list[str] = [
    "ip",
    "dns",
    "webrtc",
    "webrtclocal",
    "quic",
    "ecs",
    "killswitch",
    "splittunnel",
    "mdns",
    "interface",
    "tcptimestamp",
]

DESCRIPTIONS: dict[str, str] = {
    "ip": "IP leak (IPv4/IPv6 egress consistency vs. the tunnel)",
    "dns": "DNS leak (resolver path and recursive resolver discovery)",
    "webrtc": "WebRTC/UDP leak (STUN-mapped address vs. HTTP egress)",
    "webrtclocal": "WebRTC local-candidate leak (ICE host candidates)",
    "quic": "QUIC/UDP-443 leak (does UDP route through the tunnel)",
    "ecs": "EDNS Client Subnet disclosure (baseline + active injection)",
    "killswitch": "Kill-switch (default routes + firewall drop rules)",
    "splittunnel": "Split-tunnel (public traffic routed outside the tunnel)",
    "mdns": "mDNS/LLMNR identity broadcast on the LAN",
    "interface": "Interface/MTU fingerprint",
    "tcptimestamp": "TCP timestamp fingerprint (RFC 1323)",
}

__all__ = ["CHECKS", "ORDER", "DESCRIPTIONS"]
