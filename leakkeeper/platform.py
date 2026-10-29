"""Platform guard — leakkeeper targets Linux only.

The routing/firewall/LAN checks shell out to ``ip``, ``iptables``, ``wg``, ``ss``
and read Linux-specific files (``/etc/resolv.conf``, ``/etc/nsswitch.conf``), so
running on other OSes would silently produce wrong verdicts. We fail loudly
instead.
"""

from __future__ import annotations

import sys


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def require_linux() -> None:
    if not is_linux():
        raise OSError(
            "leakkeeper is Linux-only: routing/firewall checks require "
            "ip, iptables, wg and ss"
        )
