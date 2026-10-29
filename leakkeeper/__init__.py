"""leakkeeper — a dependency-free Linux VPN/network leak tester (CLI + library).

Detects the most common and the advanced privacy leaks in a single run:
IP (IPv4/IPv6), DNS, WebRTC/UDP (STUN), EDNS Client Subnet, kill-switch,
split-tunnel, mDNS/LLMNR, QUIC/UDP bypass and interface fingerprinting.

Linux-only: the routing/firewall/LAN checks rely on ``ip``, ``iptables``,
``wg`` and ``ss``. Pure Python (stdlib only) so it runs on any Linux host
without a package manager or network access to install dependencies.
"""

from __future__ import annotations

from ._version import __version__

__all__ = ["__version__"]
