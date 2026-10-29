"""mDNS / LLMNR check — is the host broadcasting its identity on the LAN?"""

from __future__ import annotations

import re
import shutil
import subprocess

from ..config import CheckContext
from ..result import CheckResult, Status


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _listeners() -> tuple[bool, list[str]]:
    if not shutil.which("ss"):
        return False, []
    try:
        proc = subprocess.run(
            ["ss", "-lun"], capture_output=True, text=True, timeout=10
        )
        return proc.returncode == 0, proc.stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired):
        return False, []


def _config_enabled(content: str | None, key: str) -> bool:
    if content is None:
        return False
    for line in content.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip().lower()
        if not line:
            continue
        if key == "nss":
            if re.search(r"\b(?:mdns|mdns4|mdns6|llmnr|llmnr4|llmnr6)(?:_[a-z0-9]+)?\b", line):
                return True
        elif line.startswith("multicastdns="):
            return line.split("=", 1)[1].strip() in {"yes", "resolve"}
    return False


def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(id="mdns", name="mDNS / LLMNR", category="lan")
    evidence: list[str] = []

    nss = _read("/etc/nsswitch.conf")
    mdns_nss = _config_enabled(nss, "nss")
    evidence.append(f"nsswitch mdns entries: {mdns_nss}")

    resolved_conf = _read("/etc/systemd/resolved.conf")
    resolved_mdns = _config_enabled(resolved_conf, "resolved")
    evidence.append(f"systemd-resolved MulticastDNS=yes: {resolved_mdns}")

    listeners_ok, listeners = _listeners()
    mdns_port = any(re.search(r"(?:[:.]5353|:mdns)(?:\s|$)", line) for line in listeners)
    llmnr_port = any(re.search(r"(?:[:.]5355|:llmnr)(?:\s|$)", line) for line in listeners)
    evidence.append(f"listener on 5353 (mDNS): {mdns_port}")
    evidence.append(f"listener on 5355 (LLMNR): {llmnr_port}")

    enabled = mdns_nss or resolved_mdns or mdns_port or llmnr_port

    details = {
        "nsswitch_mdns": mdns_nss,
        "resolved_multicastdns": resolved_mdns,
        "listener_5353": mdns_port,
        "listener_5355": llmnr_port,
        "nsswitch_read": nss is not None,
        "listeners_read": listeners_ok,
    }

    if nss is None or not listeners_ok:
        missing = []
        if nss is None:
            missing.append("/etc/nsswitch.conf")
        if not listeners_ok:
            missing.append("ss -lun")
        res.status = Status.ERROR
        res.summary = f"could not inspect mDNS/LLMNR state: {', '.join(missing)}"
    elif enabled:
        res.status = Status.WARN
        res.summary = (
            "mDNS/LLMNR is enabled — the host may advertise its hostname on the local "
            "network (identity disclosure on untrusted LANs)"
        )
    else:
        res.status = Status.PASS
        res.summary = "mDNS/LLMNR disabled — host does not broadcast its name"

    res.evidence = evidence
    res.details = details
    return res
