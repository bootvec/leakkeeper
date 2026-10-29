"""TCP timestamp check — kernel emits RFC 1323 timestamps (fingerprinting)."""

from __future__ import annotations

import subprocess

from ..config import CheckContext
from ..result import CheckResult, Status


def _sysctl(name: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["sysctl", "-n", name], capture_output=True, text=True, timeout=10
        )
        return proc.returncode, proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(id="tcptimestamp", name="TCP timestamp", category="fingerprint")
    evidence: list[str] = []

    ts_rc, ts = _sysctl("net.ipv4.tcp_timestamps")
    evidence.append(f"net.ipv4.tcp_timestamps = {ts or '(unreadable)'}")

    # RFC 1323 window scaling pairs with timestamps.
    ws_rc, ws = _sysctl("net.ipv4.tcp_window_scaling")
    evidence.append(f"net.ipv4.tcp_window_scaling = {ws or '(unreadable)'}")

    details = {"tcp_timestamps": ts, "tcp_window_scaling": ws}

    if ts_rc != 0:
        res.status = Status.ERROR
        res.summary = "could not read net.ipv4.tcp_timestamps"
    elif ts == "1":
        res.status = Status.WARN
        res.summary = (
            "TCP timestamps enabled — leaks system clock/uptime and enables OS "
            "fingerprinting and cross-session correlation"
        )
    elif ts == "0":
        res.status = Status.PASS
        res.summary = "TCP timestamps disabled"
    else:
        res.status = Status.ERROR
        res.summary = "could not read net.ipv4.tcp_timestamps"

    res.evidence = evidence
    res.details = details
    return res
