"""Command-line interface for leakkeeper."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import CheckContext
from .core import overall_status, run_checks
from .netutil import ip_version
from .platform import is_linux
from .report import to_json, to_markdown, to_terminal


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="leakkeeper",
        description="VPN/network leak tester (DNS, IP, WebRTC, QUIC, ECS, kill-switch, ...)",
    )
    parser.add_argument("--version", action="version", version=f"leakkeeper {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run all leak checks")
    run.add_argument("--json", action="store_true", help="output JSON")
    run.add_argument("--markdown", action="store_true", help="output Markdown report")
    run.add_argument("--only", nargs="*", help="run only these check ids")
    run.add_argument("--exclude", nargs="*", help="skip these check ids")
    run.add_argument("--expect-ip", help="expected tunnel egress IP")
    run.add_argument("--expect-ip6", help="expected tunnel IPv6 egress IP")
    run.add_argument("--expect-dns", nargs="*", help="expected resolver IP(s)")
    run.add_argument(
        "--expect-mullvad", action="store_true", help="fail unless egress is a Mullvad exit"
    )
    run.add_argument(
        "--no-private-dns", action="store_true", help="treat private DNS resolvers as a leak"
    )
    run.add_argument("--timeout", type=int, default=8, help="per-request timeout (s)")
    run.add_argument("--strict", action="store_true", help="treat warnings as failures")
    run.add_argument("--verbose", action="store_true", help="print evidence details per check")

    sub.add_parser("list", help="list available checks")

    return parser.parse_args(argv)


def _list_checks() -> str:
    from .checks import DESCRIPTIONS, ORDER

    lines = ["Available checks:"]
    for cid in ORDER:
        lines.append(f"  {cid:<12} {DESCRIPTIONS.get(cid, '')}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.command == "list":
        print(_list_checks())
        return 0

    if not is_linux():
        print(
            "leakkeeper is Linux-only: routing/firewall checks require "
            "ip, iptables, wg and ss.",
            file=sys.stderr,
        )
        return 2

    if args.only is not None and not args.only:
        print("--only requires at least one check id", file=sys.stderr)
        return 2

    if args.exclude is not None and not args.exclude:
        print("--exclude requires at least one check id", file=sys.stderr)
        return 2

    if args.timeout is not None and args.timeout <= 0:
        print("--timeout must be a positive integer", file=sys.stderr)
        return 2

    if args.expect_ip is not None and ip_version(args.expect_ip) is None:
        print(f"error: --expect-ip is not a valid IP address: {args.expect_ip}", file=sys.stderr)
        return 2

    if args.expect_ip6 is not None and ip_version(args.expect_ip6) != 6:
        print(f"error: --expect-ip6 must be an IPv6 address: {args.expect_ip6}", file=sys.stderr)
        return 2

    for ns in args.expect_dns or []:
        if ip_version(ns) is None:
            print(f"error: --expect-dns is not a valid IP address: {ns}", file=sys.stderr)
            return 2

    ctx = CheckContext(
        expect_ip=args.expect_ip,
        expect_ip6=args.expect_ip6,
        expect_dns=args.expect_dns or [],
        expect_mullvad=args.expect_mullvad,
        allow_private_dns=not args.no_private_dns,
        timeout=args.timeout,
        strict=args.strict,
    )

    try:
        results = run_checks(ctx, only=args.only, exclude=args.exclude)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    overall = overall_status(results)

    if args.json:
        print(to_json(results, overall))
    elif args.markdown:
        print(to_markdown(results, overall))
    else:
        print(to_terminal(results, overall, verbose=args.verbose))

    # exit code reflects the worst outcome (useful in CI)
    exit_codes = {"pass": 0, "warn": 0, "skip": 0, "error": 2, "fail": 1}
    if args.strict and overall == "warn":
        return 1
    return exit_codes.get(overall, 0)


if __name__ == "__main__":
    sys.exit(main())
