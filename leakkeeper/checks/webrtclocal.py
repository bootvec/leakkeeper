"""WebRTC local-candidate leak — addresses a browser would expose via ICE."""

from __future__ import annotations

from ..config import CheckContext
from ..netutil import is_private_or_local
from ..result import CheckResult, Status
from ._shared import is_tunnel_dev, run_json_result


def _interface_addresses() -> tuple[bool, list[tuple[str, str]]]:
    """Return [(interface, ip)] for non-tunnel, non-loopback interfaces."""
    out: list[tuple[str, str]] = []
    ok, interfaces = run_json_result(["ip", "-j", "addr", "show"])
    if not ok:
        return False, out
    for iface in interfaces:
        ifname = iface.get("ifname", "")
        if not ifname or is_tunnel_dev(ifname):
            continue
        for info in iface.get("addr_info", []):
            ip = info.get("local")
            if ip and ip not in ("127.0.0.1", "::1"):
                out.append((ifname, ip))
    return True, out


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(id="webrtclocal", name="WebRTC local candidate", category="identity")
    evidence: list[str] = []

    addresses_read, addrs = _interface_addresses()
    public = []
    private = []
    for ifname, ip in addrs:
        evidence.append(f"{ifname}: {ip}")
        if is_private_or_local(ip):
            private.append(f"{ip} ({ifname})")
        else:
            public.append(f"{ip} ({ifname})")

    details = {
        "addresses": [{"iface": i, "ip": a} for i, a in addrs],
        "public": public,
        "private": private,
    }

    if not addresses_read:
        res.status = Status.ERROR
        res.summary = "could not read interface addresses; WebRTC exposure is unknown"
    elif not addrs:
        res.status = Status.PASS
        res.summary = "no non-tunnel interface addresses — WebRTC has nothing to leak"
    elif public:
        res.status = Status.FAIL
        res.summary = (
            f"WebRTC host candidates would expose real public IP(s): {', '.join(public)}"
        )
    else:
        res.status = Status.WARN
        res.summary = (
            f"WebRTC host candidates would expose LAN IP(s): {', '.join(private)} "
            "(browsers may obfuscate these via mDNS)"
        )

    res.evidence = evidence
    res.details = details
    return res
