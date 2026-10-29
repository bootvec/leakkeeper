"""Shared configuration/context passed to every check."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CheckContext:
    """Immutable-ish options controlling check behaviour and verdicts."""

    expect_ip: str | None = None          # expected tunnel egress IP (IPv4/IPv6)
    expect_ip6: str | None = None         # expected tunnel IPv6 egress IP
    expect_dns: list[str] = field(default_factory=list)  # expected resolver IPs
    expect_mullvad: bool = False             # fail if egress is not a Mullvad exit
    timeout: int = 8                          # per-request timeout (seconds)
    strict: bool = False                      # warn-as-fail mode
    allow_private_dns: bool = True            # private (10.64.x, 100.64.x) DNS is OK
