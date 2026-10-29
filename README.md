# leakkeeper

[![CI](https://github.com/bootvec/leakkeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/bootvec/leakkeeper/actions)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Zero deps](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/bootvec/leakkeeper)

Dependency-free **Linux** VPN / network leak tester. Detects privacy leaks in a
single run — **without installing anything** (pure Python standard library).

> **Linux only.** The routing/firewall/LAN checks shell out to `ip`, `iptables`,
> `wg` and `ss`. Running on another OS fails loudly instead of reporting wrong
> verdicts.

## Checks

| id | What it detects |
|----|-----------------|
| `ip` | IPv4/IPv6 egress consistency vs. the tunnel |
| `dns` | DNS leak (resolver path + actual recursive resolver) |
| `webrtc` | WebRTC/UDP leak (STUN-mapped address vs. HTTP egress) |
| `webrtclocal` | WebRTC local-candidate leak (ICE host candidates) |
| `quic` | QUIC (UDP 443) routing through the tunnel |
| `ecs` | EDNS Client Subnet disclosure (baseline + active injection) |
| `killswitch` | Kill-switch (default routes + firewall DROP rules) |
| `splittunnel` | Split-tunnel (public traffic routed outside the tunnel) |
| `mdns` | mDNS/LLMNR identity broadcast on the LAN |
| `interface` | Interface / MTU fingerprint |
| `tcptimestamp` | TCP timestamp fingerprint (RFC 1323) |

## Install & run

No dependencies. Run directly:

```bash
python3 -m leakkeeper run                # human-readable table
python3 -m leakkeeper run --markdown     # Markdown report
python3 -m leakkeeper run --json         # machine-readable JSON
python3 -m leakkeeper run --only ip dns  # specific checks
python3 -m leakkeeper run --exclude mdns # skip specific checks
python3 -m leakkeeper run --expect-ip 203.0.113.10
python3 -m leakkeeper run --expect-ip6 2001:db8::1
python3 -m leakkeeper run --expect-mullvad    # fail unless on a Mullvad exit
python3 -m leakkeeper run --no-private-dns    # treat private DNS as a leak
python3 -m leakkeeper run --timeout 8 --strict
```

Or install as a CLI:

```bash
pip install .
leakkeeper run
```

## Exit codes

`0` = pass/warn/skip, `1` = leak detected (fail), `2` = error.

## Development

```bash
pip install -e ".[dev]"   # pytest + ruff
ruff check .              # lint
pytest                    # run the test suite
```

Tests mock the network/subprocess layer, so the suite runs offline and on any OS.

## Design

- **No third-party packages** — only the standard library, so it runs on any
  Linux host without `pip` or network access.
- **Proxy-safe** — "what is my IP" requests bypass `http_proxy`/`https_proxy`/
  `all_proxy`, so a configured proxy never masks the real egress address.
- **Concurrent** — the many independent requests (IP services, STUN servers,
  QUIC probes) run in parallel, so the worst-case runtime is one `--timeout`,
  not `N × --timeout`.
- **Structured output** — routing/firewall data is read via `ip -j` and
  `nft -j` JSON, not parsed from human-readable text, so it is stable across
  iproute2/nftables versions and locale.
- **Evidence-first** — every verdict carries raw evidence lines (endpoint→IP,
  resolver IPs, routes, firewall rules) so a human can verify the result.
- **Firewall-aware** — the kill-switch check reads both `iptables` and
  `nftables` OUTPUT chains (a `nft`-only host is handled, not silently missed).
- **Safe by default** — checks never install tools, change config, or send
  identifying data anywhere except the public "what is my IP" services already
  queried by every leak test.

## Heuristics & limitations

Some checks still rely on signals rather than ground truth. Where possible the
heuristics are now tighter and resolver-aware, but treat findings as starting
points for manual verification, not as proof:

- **DNS leak** — the actual recursive resolver is discovered via `whoami` names.
  A resolver that is a well-known third-party public DNS (Google, Cloudflare,
  Quad9, OpenDNS, …) is a **hard fail**, because it means DNS leaves the VPN —
  unless it belongs to the egress provider itself (Cloudflare WARP: egress and
  `1.1.1.1` are both AS13335). "Same provider" is decided by **origin ASN**
  (Team Cymru DNS, no API key), so two providers sharing a `/16` are still
  distinguished and one provider spanning many blocks is not split. When the
  ASN lookup is unavailable it falls back to `/24`, and the result is marked as
  a heuristic.
- **MTU fingerprint** — compares the tunnel MTU against the **physical** underlay
  instead of a fixed `<1400` value. The multihop signal is an overhead of more
  than 160 bytes (one encapsulation layer plus headroom), so legitimate 1380
  (Mullvad-style) and PPPoE/jumbo single-hop setups no longer false-positive.
  A tunnel MTU below the IPv6 minimum (1280) is also flagged. Still a
  heuristic — verify with the actual tunnel configuration.
- **EDNS Client Subnet** — the baseline disclosure is normal if it belongs to the
  **resolver's own** provider or the tunnel egress provider, checked by origin
  ASN with a `/24` fallback. A same-`/16` (or even same-`/24`) subnet from a
  *different* provider is therefore flagged, while geo-distributed blocks of the
  resolver's own provider are not. A resolver that echoes our injected ECS
  subnet is reported as forwarding ECS.

## Privacy / no-leak policy

This repository is public and must never contain a real machine, VPN, resolver,
LAN or public IP address, an account e-mail, an API key or an absolute home
path. RFC 5737/3849 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`, `2001:db8::/32`), private ranges and well-known public
resolvers are allowed.

`scripts/leakscan.py` checks the working tree, staged changes, a revision range
or the full git history:

```bash
python3 scripts/leakscan.py --history     # every reachable blob
python3 scripts/leakscan.py --path .      # working tree
```

Enable the local hooks once per clone:

```bash
git config core.hooksPath .githooks
```

CI runs the history scan on every push and pull request. Repository-specific
exceptions go to `.leakscan-allow` (one regex per line); extra forbidden
strings go to `.leakscan-deny`.

## License

MIT — see [LICENSE](LICENSE).
