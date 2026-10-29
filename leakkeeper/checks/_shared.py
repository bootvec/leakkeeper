"""Shared helpers used by the routing/firewall/LAN checks.

Consolidates the tunnel-interface classification and route-line parsing that
would otherwise be copy-pasted across several checks.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

# Interface name prefixes that identify a tunnel device (WireGuard, TUN/TAP,
# macOS utun, IPsec).
TUNNEL_PREFIXES = ("wg", "tun", "utun", "tap", "ipsec")


def is_tunnel_dev(dev: str) -> bool:
    """True if *dev* looks like a tunnel interface name."""
    return dev.lower().startswith(TUNNEL_PREFIXES)


def run(args: list[str]) -> tuple[int, str]:
    """Run a command, returning (returncode, combined output). Never raises."""
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


def run_json(args: list[str]) -> Any:
    """Run a command that emits JSON (ip -j / nft -j) and parse it.

    ``iproute2`` and ``nftables`` both support ``-j``/``-json`` output, which is
    stable across versions and independent of locale — unlike their default
    human-readable text. Returns [] on any failure so callers degrade to an
    empty result rather than crashing.
    """
    rc, out = run(args)
    if rc != 0 or not out:
        return []
    try:
        return json.loads(out)
    except (ValueError, TypeError):
        return []


def run_json_result(args: list[str]) -> tuple[bool, Any]:
    """Return ``(success, data)`` so checks can distinguish empty from failed."""
    rc, out = run(args)
    if rc != 0 or not out:
        return False, []
    try:
        return True, json.loads(out)
    except (ValueError, TypeError):
        return False, []


def safepart(parts: list[str], keyword: str) -> str | None:
    """Return the token following *keyword* in a route line, or None.

    ``ip route show`` lines are keyword-based (``... dev eth0 via 1.2.3.4``),
    so this is a tiny, position-independent lookup used by several checks.
    """
    if keyword in parts:
        idx = parts.index(keyword)
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None
