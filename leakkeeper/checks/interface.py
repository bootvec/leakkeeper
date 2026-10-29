"""Interface / MTU fingerprint check — tunnel vs. physical interface metadata."""

from __future__ import annotations

from ..config import CheckContext
from ..result import CheckResult, Status
from ._shared import TUNNEL_PREFIXES, is_tunnel_dev, run_json

# Container / VM / bridge virtual interfaces — not physical uplinks.
VIRTUAL_PREFIXES = TUNNEL_PREFIXES + (
    "lo", "docker", "veth", "br-", "virbr", "vnet", "vmnet", "vboxnet", "vxlan", "lxc",
)

# Upper bound for one encapsulation layer, with headroom for real-world single-
# hop setups: outer IPv6 WireGuard ≈ 80 B, OpenVPN ≈ 69 B, and providers like
# Mullvad commonly pin a 1380 MTU on a 1500 underlay (120 B). Two stacked
# tunnels add ≥120 B, so >160 B is the conservative multihop signal. A fixed
# "<1400" rule would false-positive on those legitimate single-hop 1380s.
MAX_SINGLE_HOP_OVERHEAD = 160


def _interfaces() -> list[tuple[str, str]]:
    """Return [(name, mtu)] for interfaces from `ip -j link show`."""
    out: list[tuple[str, str]] = []
    for link in run_json(["ip", "-j", "link", "show"]):
        name = link.get("ifname")
        mtu = link.get("mtu")
        if name and mtu is not None:
            out.append((name, str(mtu)))
    return out


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(id="interface", name="Interface / MTU fingerprint", category="fingerprint")
    evidence: list[str] = []

    ifaces = _interfaces()
    tunnel_ifaces = [(n, m) for n, m in ifaces if is_tunnel_dev(n)]
    phys_ifaces = [
        (n, m) for n, m in ifaces
        if not n.lower().startswith(tuple(prefix.lower() for prefix in VIRTUAL_PREFIXES))
    ]

    for name, mtu in ifaces:
        evidence.append(f"interface {name}: mtu {mtu}")

    details = {
        "tunnel_interfaces": tunnel_ifaces,
        "physical_interfaces": phys_ifaces,
        "max_single_hop_overhead": MAX_SINGLE_HOP_OVERHEAD,
    }

    issues: list[str] = []

    # MTU fingerprinting: compare against the physical underlay instead of a
    # fixed absolute MTU. A gap above one encapsulation layer's maximum (with
    # headroom) implies a nested/multihop tunnel; this adapts to jumbo-frame and
    # PPPoE underlays and does not flag legitimate 1380-1420 single-hop tunnels.
    phys_mtus = [int(m) for _, m in phys_ifaces if m.isdigit()]
    tun_mtus = [int(m) for _, m in tunnel_ifaces if m.isdigit()]
    if phys_mtus and tun_mtus:
        phys_mtu = min(phys_mtus)
        tun_mtu = min(tun_mtus)  # effective (bottleneck) MTU
        overhead = phys_mtu - tun_mtu
        details["tunnel_overhead"] = overhead
        if overhead > MAX_SINGLE_HOP_OVERHEAD:
            issues.append(
                f"large tunnel MTU overhead ({overhead} bytes: {tun_mtu} vs physical "
                f"{phys_mtu}) — suggests a nested/multihop tunnel"
            )
        elif tun_mtu < 1280:
            issues.append(
                f"tunnel MTU {tun_mtu} is below the IPv6 minimum (1280) — IPv6 is broken"
            )

    if not tunnel_ifaces:
        res.status = Status.WARN
        res.summary = "no tunnel interface detected — are you sure a VPN is active?"
    elif issues:
        res.status = Status.WARN
        res.summary = "; ".join(issues)
    else:
        res.status = Status.PASS
        res.summary = (
            f"tunnel interface(s) {[n for n, _ in tunnel_ifaces]} present, "
            "MTU within normal VPN range"
        )

    res.evidence = evidence
    res.details = details
    return res
