#!/usr/bin/env python3
"""leakscan — block accidental privacy leaks before they are committed or shared.

Detects:
  * public IPv4/IPv6 addresses (private, loopback, link-local, CGNAT, multicast
    and RFC 5737/3849 documentation ranges are allowed)
  * e-mail addresses (GitHub noreply and example.com are allowed)
  * MAC addresses
  * private key material and common API-token formats
  * absolute home-directory paths that reveal a username
  * repository-specific deny-list regexes from ``.leakscan-deny``

Allowed values can be extended per repository with ``.leakscan-allow`` (one
regular expression per line). Both files live in the repository root.

Exit status: 0 = clean, 1 = findings, 2 = usage/git error.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Iterator, Sequence

# ---------------------------------------------------------------------------
# Allow-lists
# ---------------------------------------------------------------------------

# RFC 5737 / RFC 3849 documentation ranges are intentionally allowed, as are
# private, loopback, link-local, CGNAT, benchmarking and multicast ranges.
_ALLOW_V4_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        # Deliberate test fixture: same /16 as 198.51.100.0/24, different /24.
        # Used by tests/test_checks.py to exercise the same-/16 heuristic.
        "198.51.101.0/24",
    )
]

# Public addresses that are placeholders in documentation/tests, not secrets.
_ALLOW_V4_HOSTS = {
    "1.2.3.4",  # generic placeholder
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "64.6.64.6",
    "64.6.65.6",
    "77.88.8.8",
    "77.88.8.1",
    "4.2.2.1",
    "4.2.2.2",
    "4.2.2.3",
    "4.2.2.4",
}

_ALLOW_V6_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "2606:4700:4700::/48",  # Cloudflare public DNS
        "2001:4860::/32",  # Google public DNS
    )
]

_EMAIL_ALLOW = re.compile(
    r"(?i)^(?:[^@\s]+@users\.noreply\.github\.com|noreply@github\.com|"
    r"git@github\.com|[^@\s]+@example\.(?:com|org|net)|[^@\s]+@localhost)$"
)

# Values that are clearly placeholders, not real secrets.
_PLACEHOLDER = re.compile(
    r"(?i)(?:redacted|placeholder|changeme|change-me|example|dummy|sample|"
    r"your[-_]|<[^>]*>|\*{3,}|x{4,}|\.\.\.)"
)

_HOME_ALLOW = {"runner", "user", "users", "example", "test", "you", "username", "localhost"}

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(
    r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])"
    r"|(?<![\w:])::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{0,4}(?![\w:])"
)
_MAC_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
_HOME_RE = re.compile(r"(?<![\w.-])/(?:home|Users)/([A-Za-z0-9._-]+)")
_WIN_HOME_RE = re.compile(r"(?i)(?<![\w.-])[A-Z]:\\Users\\([A-Za-z0-9._-]+)")

_SECRET_PATTERNS: Sequence[tuple[str, re.Pattern[str]]] = (
    ("private key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    (
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    ("AWS key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "WireGuard/base64 key material",
        re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/])"),
    ),
)

_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
)

_UNQUOTED_SECRET_RE = re.compile(
    r"(?i)^\s*(?:password|passwd|client_access_token|client_refresh_token|"
    r"client_salted_key_pass)\s*=\s*(\S{8,})\s*$"
)

_SENSITIVE_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}
_SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "leakkeeper.egg-info",
    "dist",
    "build",
}

_SKIP_FILES = {".leakscan-allow", ".leakscan-deny"}

_MAX_BYTES = 2 * 1024 * 1024

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class Finding:
    __slots__ = ("location", "line", "reason", "value")

    def __init__(self, location: str, line: int, reason: str, value: str) -> None:
        self.location = location
        self.line = line
        self.reason = reason
        self.value = value

    def __str__(self) -> str:
        where = self.location if self.line <= 0 else f"{self.location}:{self.line}"
        return f"{where}  {self.reason}: {_redact(self.value)}"


def _redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "…" + "*" * min(8, len(value) - 4)


# ---------------------------------------------------------------------------
# Allow / deny helpers
# ---------------------------------------------------------------------------


def _load_patterns(path: str) -> list[re.Pattern[str]]:
    if not os.path.isfile(path):
        return []
    patterns: list[re.Pattern[str]] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                patterns.append(re.compile(line))
            except re.error as exc:
                print(f"leakscan: bad regex in {path}: {line!r} ({exc})", file=sys.stderr)
                raise SystemExit(2) from exc
    return patterns


def _user_config(name: str) -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "leakscan", name)


def _repo_root() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip() or None


def _is_allowed_v4(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return True
    if not addr.is_global:
        return True
    if str(addr) in _ALLOW_V4_HOSTS:
        return True
    return any(addr in net for net in _ALLOW_V4_NETS)


def _is_allowed_v6(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return True
    if not addr.is_global:
        return True
    return any(addr in net for net in _ALLOW_V6_NETS)


def _is_placeholder(value: str) -> bool:
    if value.startswith(("$", "%", "{")):
        return True
    return bool(_PLACEHOLDER.search(value))


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def scan_text(
    location: str,
    text: str,
    allow: Sequence[re.Pattern[str]],
    deny: Sequence[re.Pattern[str]],
    start_line: int = 1,
) -> Iterator[Finding]:
    for lineno, line in enumerate(text.splitlines(), start_line):
        if any(p.search(line) for p in allow):
            continue

        for pattern in deny:
            for match in pattern.finditer(line):
                yield Finding(location, lineno, "deny-list", match.group(0))

        for match in _IPV4_RE.finditer(line):
            value = match.group(0)
            if not _is_allowed_v4(value):
                yield Finding(location, lineno, "public IPv4", value)

        for match in _IPV6_RE.finditer(line):
            value = match.group(0)
            if _is_allowed_v6(value):
                continue
            if any(p.search(value) for p in allow):
                continue
            yield Finding(location, lineno, "public IPv6", value)

        for match in _MAC_RE.finditer(line):
            yield Finding(location, lineno, "MAC address", match.group(0))

        for match in _EMAIL_RE.finditer(line):
            value = match.group(0)
            if _EMAIL_ALLOW.match(value):
                continue
            yield Finding(location, lineno, "e-mail address", value)

        for match in _HOME_RE.finditer(line):
            if match.group(1).lower() not in _HOME_ALLOW:
                yield Finding(location, lineno, "home path", match.group(0))
        for match in _WIN_HOME_RE.finditer(line):
            if match.group(1).lower() not in _HOME_ALLOW:
                yield Finding(location, lineno, "home path", match.group(0))

        for reason, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(0)
                if _is_placeholder(value):
                    continue
                yield Finding(location, lineno, reason, value)

        for match in _SECRET_ASSIGN_RE.finditer(line):
            value = match.group(1)
            if _is_placeholder(value):
                continue
            yield Finding(location, lineno, "secret assignment", value)

        match = _UNQUOTED_SECRET_RE.match(line)
        if match and not _is_placeholder(match.group(1)):
            yield Finding(location, lineno, "secret assignment (unquoted)", match.group(1))


def _scan_filename(path: str, allow: Sequence[re.Pattern[str]]) -> Iterator[Finding]:
    name = os.path.basename(path).lower()
    sensitive = name in _SENSITIVE_FILENAMES or name.endswith(_SENSITIVE_SUFFIXES)
    if sensitive and not any(p.search(path) for p in allow):
        yield Finding(path, 0, "sensitive filename", path)


def _iter_files(root: str) -> Iterator[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def _read_text(path: str) -> str | None:
    try:
        if os.path.getsize(path) > _MAX_BYTES or os.path.islink(path):
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    return data.decode("utf-8", errors="replace")


def scan_path(
    root: str,
    allow: Sequence[re.Pattern[str]],
    deny: Sequence[re.Pattern[str]],
) -> Iterator[Finding]:
    for path in _iter_files(root):
        if os.path.basename(path) in _SKIP_FILES:
            continue
        rel = os.path.relpath(path, root) if os.path.isdir(root) else path
        yield from _scan_filename(rel, allow)
        text = _read_text(path)
        if text is not None:
            yield from scan_text(rel, text, allow, deny)


def _git(*args: str, text: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=text,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            proc.stderr.decode("utf-8", "replace") if not text else proc.stderr
        )
    return proc.stdout if text else proc.stdout.decode("utf-8", "replace")


def _parse_diff(diff: str) -> Iterator[tuple[str, int, str]]:
    current: str | None = None
    new_line = 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:]
            if path == "/dev/null":
                current = None
            else:
                current = path[2:] if path.startswith("b/") else path
            continue
        if raw.startswith("--- "):
            continue
        if raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            new_line = int(match.group(1)) if match else 1
            continue
        if current is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            yield current, new_line, raw[1:]
            new_line += 1
        elif raw.startswith(" "):
            new_line += 1
        elif raw.startswith("\\"):
            continue


def scan_diff(
    diff: str,
    allow: Sequence[re.Pattern[str]],
    deny: Sequence[re.Pattern[str]],
) -> Iterator[Finding]:
    for path, lineno, line in _parse_diff(diff):
        if os.path.basename(path) in _SKIP_FILES:
            continue
        yield from _scan_filename(path, allow)
        yield from scan_text(path, line, allow, deny, start_line=lineno)


def _blobs_for_rev_range(rev_range: str) -> Iterator[tuple[str, str]]:
    args = shlex.split(rev_range)
    out = _git("rev-list", "--objects", *args)
    seen = set()
    for raw in out.splitlines():
        parts = raw.split(" ", 1)
        sha = parts[0]
        path = parts[1] if len(parts) == 2 else "<unknown>"
        if sha in seen:
            continue
        seen.add(sha)
        yield sha, path


def scan_blobs(
    rev_args: Sequence[str],
    allow: Sequence[re.Pattern[str]],
    deny: Sequence[re.Pattern[str]],
) -> Iterator[Finding]:
    """Scan every blob reachable from ``rev_args`` (deduplicated by object id)."""
    seen = set()
    for sha, path in _blobs_for_rev_range(" ".join(shlex.quote(a) for a in rev_args)):
        if sha in seen or os.path.basename(path) in _SKIP_FILES:
            continue
        seen.add(sha)
        try:
            obj_type = _git("cat-file", "-t", sha).strip()
        except RuntimeError:
            continue
        if obj_type != "blob":
            continue
        try:
            data = subprocess.run(
                ["git", "cat-file", "blob", sha],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).stdout
        except OSError:
            continue
        if len(data) > _MAX_BYTES or b"\x00" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        yield from scan_text(f"blob {sha[:12]} ({path})", text, allow, deny)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan for privacy leaks before committing or sharing."
    )
    parser.add_argument("--staged", action="store_true", help="scan staged changes")
    parser.add_argument(
        "--range",
        metavar="REV",
        help="scan objects in a git revision range (e.g. origin/main..HEAD)",
    )
    parser.add_argument("--history", action="store_true", help="scan all reachable git objects")
    parser.add_argument("--path", metavar="PATH", help="scan a file or directory (default: .)")
    parser.add_argument("--quiet", action="store_true", help="only print the summary")
    args = parser.parse_args(argv)

    root = _repo_root() or os.getcwd()
    allow = _load_patterns(os.path.join(root, ".leakscan-allow"))
    allow += _load_patterns(_user_config("allow"))
    deny = _load_patterns(os.path.join(root, ".leakscan-deny"))
    deny += _load_patterns(_user_config("deny"))

    findings: list[Finding] = []
    try:
        if args.staged:
            diff = _git("diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff")
            findings.extend(scan_diff(diff, allow, deny))
            for path in _git("diff", "--cached", "--name-only", "--diff-filter=ACMR").splitlines():
                findings.extend(_scan_filename(path, allow))
        elif args.range:
            findings.extend(scan_blobs(shlex.split(args.range), allow, deny))
        elif args.history:
            findings.extend(scan_blobs(["--all"], allow, deny))
        else:
            findings.extend(scan_path(args.path or ".", allow, deny))
    except RuntimeError as exc:
        print(f"leakscan: git error: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        for finding in findings:
            print(f"LEAK  {finding}")

    if findings:
        print(f"leakscan: {len(findings)} finding(s). Commit/push/share blocked.", file=sys.stderr)
        return 1

    print("leakscan: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
