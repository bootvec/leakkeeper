"""Split-tunnel check — is any public traffic routed outside the tunnel?"""

from __future__ import annotations

import ipaddress

from ..config import CheckContext
from ..netutil import DOCUMENTATION_NETWORKS
from ..result import CheckResult, Status
from ._shared import TUNNEL_PREFIXES, run_json_result
from ._shared import run as run_cmd


def _tunnel_endpoints() -> set[str]:
    """Peer endpoint IPs of WireGuard tunnels (entry/exit servers)."""
    ips: set[str] = set()
    rc, out = run_cmd(["wg", "show", "all", "endpoints"])
    if rc != 0:
        return ips
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        # format: <iface> <peer-pubkey> <ip>:<port>  (IPv6 is [addr]:port)
        ep = parts[2]
        if ep.startswith("["):
            ep = ep[1:].split("]", 1)[0]
        else:
            ep = ep.rsplit(":", 1)[0]
        ips.add(ep)
    return ips


def _host_connected_networks() -> tuple[bool, set[str]]:
    """Networks the host is directly attached to (from its own addresses)."""
    nets: set[str] = set()
    ok, interfaces = run_json_result(["ip", "-j", "addr", "show"])
    if not ok:
        return False, nets
    for iface in interfaces:
        for info in iface.get("addr_info", []):
            local = info.get("local")
            if not local:
                continue
            try:
                iface_obj = ipaddress.ip_interface(
                    f"{local}/{info.get('prefixlen', 0)}"
                )
                nets.add(str(iface_obj.network))
            except ValueError:
                continue
    return True, nets


# CGNAT (RFC 6598) is IPv4-only shared address space; treat it as non-public.
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


def _is_public(dst: str) -> bool:
    try:
        net = ipaddress.ip_network(dst, strict=False)
    except ValueError:
        return False
    if any(net.subnet_of(doc) for doc in DOCUMENTATION_NETWORKS if net.version == doc.version):
        return True  # RFC 5737 documentation ranges are treated as public
    return (
        not net.is_private
        and not net.is_link_local
        and not net.is_loopback
        and not net.is_multicast
        and not net.is_reserved
        and not net.is_unspecified
        and not (net.version == 4 and net.subnet_of(_CGNAT_V4))
    )


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(id="splittunnel", name="Split-tunnel", category="routing")
    evidence: list[str] = []

    endpoints = _tunnel_endpoints()
    evidence.append(f"tunnel endpoints: {sorted(endpoints) or '(none)'}")

    addresses_read, own_nets = _host_connected_networks()
    if not addresses_read:
        evidence.append("host-connected networks: (unavailable)")
    elif own_nets:
        evidence.append(f"host-connected networks: {sorted(own_nets)}")

    bypass: list[str] = []
    bypass_details: list[dict[str, str]] = []
    route_read_errors: list[str] = [] if addresses_read else ["interface addresses"]
    for fam in ("-4", "-6"):
        ok, routes = run_json_result(["ip", "-j", fam, "route", "show", "table", "all"])
        if not ok:
            route_read_errors.append(f"IPv{fam.removeprefix('-')} route table")
            continue
        for r in routes:
            dst = r.get("dst")
            if not dst or dst == "default":
                continue
            dev = r.get("dev")
            if dev is None or dev.startswith(TUNNEL_PREFIXES):
                continue
            proto = r.get("protocol", "")
            via = r.get("gateway")
            # Kernel auto-connected routes are the host's own subnets — not a split.
            if proto == "kernel":
                continue
            # Host route to the tunnel's own endpoint is expected.
            if dst.split("/")[0] in endpoints:
                continue
            if not _is_public(dst):
                continue
            table = str(r.get("table", "unknown"))
            protocol = str(r.get("protocol", "unknown"))
            desc = f"{fam} {dst} dev {dev}" + (f" via {via}" if via else "")
            desc += f" (table {table}, protocol {protocol})"
            bypass.append(desc)
            bypass_details.append(
                {
                    "family": fam.removeprefix("-"),
                    "destination": str(dst),
                    "device": str(dev),
                    "gateway": str(via or ""),
                    "table": table,
                    "protocol": protocol,
                }
            )
            evidence.append(f"[split] {desc}")

    details = {
        "tunnel_endpoints": sorted(endpoints),
        "host_networks": sorted(own_nets),
        "bypass_routes": bypass,
        "bypass_route_details": bypass_details,
        "route_read_errors": route_read_errors,
    }

    if route_read_errors:
        res.status = Status.ERROR
        res.summary = f"could not read routing table(s): {', '.join(route_read_errors)}"
    elif bypass:
        res.status = Status.WARN
        res.summary = (
            f"{len(bypass)} route(s) send public traffic outside the tunnel "
            f"(split-tunnel): {bypass[0]}"
        )
    else:
        res.status = Status.PASS
        res.summary = "no public traffic routed outside the tunnel"

    res.evidence = evidence
    res.details = details
    return res
