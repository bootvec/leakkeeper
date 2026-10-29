"""Low-level networking helpers (stdlib only).

Contains the primitives every check relies on: HTTP GET, IP address
classification, a minimal DNS client (with EDNS Client Subnet support),
and a STUN Binding-Request client for discovering the UDP egress address.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import random
import socket
import struct
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from ._version import __version__

DEFAULT_TIMEOUT = 8
MAGIC_COOKIE = 0x2112A442

# RFC 5737 (IPv4) and RFC 3849 (IPv6) documentation ranges (TEST-NET). These
# are not real private/local addresses — they exist only for documentation and
# examples, and Python's ``is_private``/``is_reserved`` classifies them
# inconsistently across versions. Treating them as public keeps fixtures
# deterministic without embedding anyone's real IPs.
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

_USER_AGENT = f"leakkeeper/{__version__}"
_MAX_HTTP_BODY = 1024 * 1024

# An opener that ignores environment proxy variables (http_proxy/https_proxy/
# all_proxy). A leak test must measure the host's own egress, so routing the
# "what is my IP" requests through a user-configured proxy would return the
# proxy's address instead and produce wrong verdicts.
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# DNS RR type → name (used to label parsed answer records with their real type).
DNS_TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 16: "TXT", 28: "AAAA",
    33: "SRV", 65: "HTTPS",
}

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def http_get(url: str, timeout: int = DEFAULT_TIMEOUT) -> bytes | None:
    """Return response body bytes or None on any failure. Never raises."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with _NO_PROXY_OPENER.open(req, timeout=timeout) as resp:
            length = resp.headers.get("Content-Length")
            if length:
                try:
                    if int(length) > _MAX_HTTP_BODY:
                        return None
                except ValueError:
                    pass
            body = resp.read(_MAX_HTTP_BODY + 1)
            return body if len(body) <= _MAX_HTTP_BODY else None
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        return None


def http_get_json(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any] | None:
    body = http_get(url, timeout)
    if body is None:
        return None
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None


def http_get_text(url: str, timeout: int = DEFAULT_TIMEOUT) -> str | None:
    body = http_get(url, timeout)
    if body is None:
        return None
    return body.decode("utf-8", "replace").strip()


def parallel_map(fn: Callable[..., Any], items: list[Any]) -> list[Any]:
    """Run *fn* over *items* concurrently and return results in order.

    Every network check issues several independent requests (multiple IP
    services, multiple STUN servers, ...) that previously ran strictly
    serially, each waiting up to ``timeout``. Running them in parallel cuts the
    worst-case runtime from ``N * timeout`` to roughly one ``timeout``.
    """
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=len(items)) as ex:
        return list(ex.map(fn, items))


# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------

def _ip_obj(value: str) -> Any | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_private_or_local(ip: str) -> bool:
    """True for loopback, private (RFC1918), link-local, CGNAT and VPN pools.

    RFC 5737 documentation ranges (``192.0.2.0/24``, ``198.51.100.0/24``,
    ``203.0.113.0/24``) are treated as *public* — they are not real private or
    local addresses, exist only for examples/tests, and Python's ``is_private``
    classifies them inconsistently across versions.
    """
    obj = _ip_obj(ip)
    if obj is None:
        return False
    if any(obj in net for net in DOCUMENTATION_NETWORKS):
        return False
    return (
        obj.is_loopback
        or obj.is_private
        or obj.is_link_local
        or obj.is_reserved
        or obj.is_multicast
        or obj.is_unspecified
        or obj in ipaddress.ip_network("100.64.0.0/10")
    )


def ip_version(ip: str) -> int | None:
    obj = _ip_obj(ip)
    return None if obj is None else obj.version


def neighborhood(ip: str, prefix: int = 0) -> str:
    """Return the /16 (IPv4) or /48 (IPv6) network address for coarse comparison."""
    obj = _ip_obj(ip)
    if obj is None:
        return ip
    p = prefix or (16 if obj.version == 4 else 48)
    try:
        return str(ipaddress.ip_network(f"{obj}/{p}", strict=False).network_address)
    except ValueError:
        return ip


def same_subnet(
    a: str, b: str, v4_prefix: int = 24, v6_prefix: int = 64
) -> bool:
    """True if *a* and *b* are in the same subnet (default /24 v4, /64 v6).

    A /24 (not /16) is used so a resolver/egress one block away is not treated as
    "the same provider" — that tightens leak detection without an ASN database.
    """
    oa, ob = _ip_obj(a), _ip_obj(b)
    if oa is None or ob is None or oa.version != ob.version:
        return False
    if oa.version == 4:
        return neighborhood(a, v4_prefix) == neighborhood(b, v4_prefix)
    return neighborhood(a, v6_prefix) == neighborhood(b, v6_prefix)


# ---------------------------------------------------------------------------
# DNS (system resolver)
# ---------------------------------------------------------------------------

def _getaddrinfo(host: str, timeout: int = DEFAULT_TIMEOUT) -> list[Any]:
    """getaddrinfo in a worker thread so a slow resolver cannot hang the check.

    ``socket.getaddrinfo`` has no timeout argument and blocks the calling thread
    until the resolver answers. Running it in a daemon thread and joining with a
    bounded wait lets us honour the per-check timeout instead of stalling.
    """
    result: list[Any] = []
    errors: list[Exception] = []

    def work() -> None:
        try:
            result.extend(socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM))
        except Exception as exc:  # any resolution failure behaves like "no answer"
            errors.append(exc)

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive() or errors:
        return []
    return result


def resolve_a(host: str, timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    """Resolve A/AAAA records via the system resolver. Returns sorted unique IPs.

    Unspecified (``0.0.0.0`` / ``::``), loopback, link-local and multicast
    results are dropped so synthetic DNS64/NAT64 answers never pollute the
    evidence.
    """
    infos = _getaddrinfo(host, timeout)
    ips: list[str] = []
    for info in infos:
        if not info[4]:
            continue
        ip = info[4][0]
        obj = _ip_obj(ip)
        if obj is None:
            continue
        if obj.is_unspecified or obj.is_loopback or obj.is_multicast or obj.is_link_local:
            continue
        if ip not in ips:
            ips.append(ip)
    return sorted(ips)


# "whoami" names: the A record each one returns is the recursive resolver's own
# IP, which lets us discover the actual resolver behind a stub (e.g. 127.0.0.53).
WHOAMI_NAMES = ("whoami.akamai.net", "whoami.ultradns.net")


def resolver_ips(timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    """Public recursive resolver IP(s) discovered via whoami names."""
    found: list[str] = []
    for name in WHOAMI_NAMES:
        for ip in resolve_a(name, timeout):
            if ip not in found:
                found.append(ip)
    return found


def _cymru_origin_name(ip: str) -> str | None:
    """Team Cymru origin-ASN DNS name for *ip* (no API key required)."""
    obj = _ip_obj(ip)
    if obj is None:
        return None
    if obj.version == 4:
        reverse = ".".join(reversed(str(obj).split(".")))
    else:
        reverse = obj.reverse_pointer
    return f"{reverse}.origin.asn.cymru.com"


def asn_lookup(ip: str, timeout: int = 5, server: str | None = None) -> int | None:
    """Return the origin ASN of *ip* via Team Cymru's DNS service.

    Ownership is identified by ASN rather than by address proximity: two
    providers can share a /16 (or even a /24) while different blocks of one
    provider can be far apart. Returns ``None`` when the lookup is unavailable,
    in which case callers fall back to prefix comparison.
    """
    name = _cymru_origin_name(ip)
    if not name:
        return None
    servers = [server] if server else system_nameservers()
    for srv in servers[:2]:
        for rec in dns_query(name, 16, srv, timeout=timeout):
            first = str(rec.get("value", "")).split("|", 1)[0].strip()
            if first[:2].upper() == "AS":
                first = first[2:]
            if first.isdigit():
                return int(first)
    return None


def system_nameservers() -> list[str]:
    """Parse /etc/resolv.conf and return the configured nameservers (Linux)."""
    servers: list[str] = []
    path = "/etc/resolv.conf"
    if not os.path.exists(path):
        return servers
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if parts and parts[0].lower() == "nameserver" and len(parts) > 1:
                    servers.append(parts[1])
    except OSError:
        return servers
    return servers


# ---------------------------------------------------------------------------
# Minimal DNS client (for direct queries, e.g. ECS reflection)
# ---------------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            raw = b""
        else:
            try:
                raw = label.encode("idna")
            except UnicodeError:
                raw = label.encode("utf-8", "replace")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def _build_query(name: str, qtype: int, ecs: str | None = None) -> bytes:
    """Build a DNS query with optional EDNS Client Subnet (RFC 7871)."""
    txid = random.getrandbits(16)
    question = _encode_name(name) + struct.pack(">HH", qtype, 1)
    additional = b""
    if ecs:
        obj = _ip_obj(ecs)
        if obj is not None:
            family = 1 if obj.version == 4 else 2
            if family == 1:
                addr = struct.pack(">I", int(obj))[:3]
                prefix = 24
            else:
                addr = int(obj).to_bytes(16, "big")[:6]
                prefix = 48
            # RFC 7871 option: code(2)=8, length(2), family(2), src-prefix(1), scope(1), addr
            opt_rdata = struct.pack(">HHHBB", 8, 4 + len(addr), family, prefix, 0) + addr
            additional = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, len(opt_rdata)) + opt_rdata
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 1 if additional else 0)
    return header + question + additional


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    hops = 0
    while True:
        if offset < 0 or offset >= len(data):
            return ".".join(labels), end
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                return ".".join(labels), end
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            if hops > 16:  # guard against pointer loops
                return ".".join(labels), end
            continue
        offset += 1
        if offset + length > len(data):
            return ".".join(labels), end
        labels.append(data[offset : offset + length].decode("utf-8", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels), end


def dns_query(
    name: str,
    qtype: int,
    server: str,
    port: int = 53,
    timeout: int = 5,
    ecs: str | None = None,
) -> list[dict[str, Any]]:
    """Send a DNS query over UDP and return parsed answer records."""
    answers: list[dict[str, Any]] = []
    query = _build_query(name, qtype, ecs)

    try:
        addrinfos = socket.getaddrinfo(server, port, type=socket.SOCK_DGRAM)
    except OSError:
        return answers
    if not addrinfos:
        return answers
    family, _, _, _, sockaddr = addrinfos[0]

    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, sockaddr)
        data, _ = sock.recvfrom(4096)
    except (OSError, socket.timeout):
        return answers
    finally:
        sock.close()

    if len(data) < 12:
        return answers
    txid = query[:2]
    flags = struct.unpack(">H", data[2:4])[0]
    if data[:2] != txid or not (flags & 0x8000) or (flags & 0x000F):
        return answers
    qdcount, ancount = struct.unpack(">HH", data[4:8])
    if qdcount != 1:
        return answers
    offset = 12
    # skip question section
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        if offset + 4 > len(data):
            return answers
        offset += 4
    for _ in range(ancount):
        _, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):  # truncated answer record — stop cleanly
            break
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        rec: dict[str, Any] = {
            "type": DNS_TYPE_NAMES.get(rtype, str(rtype)),
            "class": rclass,
            "ttl": ttl,
        }
        if rtype == 1 and rdlength == 4:
            rec["value"] = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == 28 and rdlength == 16:
            rec["value"] = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 2 or rtype == 5:
            rec["value"], _ = _decode_name(data, offset - rdlength)
        elif rtype == 16:
            parts = []
            i = 0
            while i < len(rdata):
                n = rdata[i]
                if i + 1 + n > len(rdata):  # truncated length byte — bail out
                    n = len(rdata) - i - 1
                if n <= 0:
                    break
                parts.append(rdata[i + 1 : i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
            rec["value"] = "".join(parts)
        else:
            rec["value"] = rdata.hex()
        answers.append(rec)
    return answers


# ---------------------------------------------------------------------------
# STUN client (WebRTC / UDP egress discovery)
# ---------------------------------------------------------------------------

def stun_mapped_address(
    server: str, port: int = 19302, timeout: int = 5
) -> tuple[str | None, int | None, str | None]:
    """Return (mapped_ip, mapped_port, method) from a STUN Binding Request.

    Uses the XOR-MAPPED-ADDRESS (RFC 5389) attribute first, then falls back
    to the legacy MAPPED-ADDRESS. The mapped address is the public address
    the STUN server sees for our UDP socket — i.e. our UDP egress. Both IPv4
    (family 0x01) and IPv6 (family 0x02) mappings are parsed; IPv4 is tried
    first, with IPv6 as a fallback (e.g. on IPv6-only hosts).
    """
    txid = random.getrandbits(96)
    request = struct.pack(">HHI", 0x0001, 0, MAGIC_COOKIE) + txid.to_bytes(12, "big")

    try:
        addrinfos = socket.getaddrinfo(server, port, type=socket.SOCK_DGRAM)
    except OSError:
        return None, None, None
    # Prefer IPv4 so dual-stack hosts keep the fast path; IPv6 is still
    # exercised on IPv6-only hosts.
    addrinfos = sorted(addrinfos, key=lambda a: a[0] != socket.AF_INET)

    for family, _socktype, _proto, _canon, sockaddr in addrinfos:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(request, sockaddr)
            data, _ = sock.recvfrom(2048)
        except (OSError, socket.timeout):
            continue
        finally:
            sock.close()
        result = _parse_stun_response(data, txid)
        if result[0] is not None:
            return result

    return None, None, None


def _parse_stun_response(
    data: bytes, txid: int
) -> tuple[str | None, int | None, str | None]:
    """Parse a STUN Binding Success Response into (ip, port, method)."""
    if len(data) < 20 or data[:2] != b"\x01\x01":
        return None, None, None
    # The response transaction ID must match our request; otherwise the packet
    # is a stray/duplicated datagram from a previous socket and is discarded.
    if data[8:20] != txid.to_bytes(12, "big"):
        return None, None, None
    length = struct.unpack(">H", data[2:4])[0]
    body = data[20 : 20 + length]

    mapped: tuple[str | None, int | None, str | None] | None = None
    xor: tuple[str | None, int | None, str | None] | None = None
    offset = 0
    while offset + 4 <= len(body):
        atype, alen = struct.unpack(">HH", body[offset : offset + 4])
        value = body[offset + 4 : offset + 4 + alen]
        if len(value) < alen:  # truncated attribute — stop rather than index past it
            break
        if atype == 0x0020 and alen >= 8:  # XOR-MAPPED-ADDRESS
            family = value[1]
            xport = struct.unpack(">H", value[2:4])[0] ^ (MAGIC_COOKIE >> 16)
            if family == 0x01:
                xaddr = struct.unpack(">I", value[4:8])[0] ^ MAGIC_COOKIE
                xor = (
                    socket.inet_ntop(socket.AF_INET, struct.pack(">I", xaddr)),
                    xport,
                    "xor-mapped",
                )
            elif family == 0x02 and alen >= 20:
                raw = int.from_bytes(value[4:20], "big")
                xaddr = raw ^ ((MAGIC_COOKIE << 96) | txid)
                xor = (
                    socket.inet_ntop(socket.AF_INET6, xaddr.to_bytes(16, "big")),
                    xport,
                    "xor-mapped",
                )
        elif atype == 0x0001 and alen >= 8:  # MAPPED-ADDRESS (legacy, IPv4 only)
            family = value[1]
            mport = struct.unpack(">H", value[2:4])[0]
            if family == 0x01:
                mapped = (
                    socket.inet_ntop(socket.AF_INET, value[4:8]),
                    mport,
                    "mapped",
                )
        offset += 4 + alen
        if offset % 4:
            offset += 4 - (offset % 4)

    return xor or mapped or (None, None, None)
