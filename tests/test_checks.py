"""Unit tests for the deterministic verdict logic of each check.

These tests mock the subprocess/file/socket layer and assert that each check
correctly (a) flags a real leak/misconfiguration and (b) stays silent (PASS)
when there is none. Network checks are tested through their classification
logic by mocking the netutil primitives they depend on.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from leakkeeper import checks, core
from leakkeeper.config import CheckContext
from leakkeeper.result import Status


def ctx(**kw) -> CheckContext:
    return CheckContext(**kw)


def fake_proc(stdout="", returncode=0, stderr=""):
    class P:
        pass

    p = P()
    p.stdout = stdout
    p.stderr = stderr
    p.returncode = returncode
    return p


class KillSwitchTest(unittest.TestCase):
    def _routes_json(self, routes):
        return patch.object(
            checks.killswitch, "run_json_result", side_effect=lambda args, **kw: (True, routes)
        )

    def test_physical_fallback_no_drop_is_fail(self):
        routes = [
            {"dst": "default", "dev": "wg-exit", "table": "100"},
            {"dst": "default", "gateway": "203.0.113.1", "dev": "eth0", "table": "main"},
        ]
        with patch.object(checks.killswitch, "run_json_result", return_value=(True, routes)), \
             patch.object(checks.killswitch, "run_json", return_value=[]), \
             patch.object(checks.killswitch, "run_cmd", return_value=(0, "-P OUTPUT ACCEPT")):
            r = checks.killswitch.run(ctx())
        self.assertEqual(r.status, Status.FAIL)

    def test_tunnel_only_is_pass(self):
        routes = [{"dst": "default", "dev": "wg-exit", "table": "100"}]
        with patch.object(checks.killswitch, "run_json_result", return_value=(True, routes)), \
             patch.object(checks.killswitch, "run_cmd", return_value=(0, "-P OUTPUT ACCEPT")):
            r = checks.killswitch.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_physical_fallback_with_drop_is_pass(self):
        routes = [
            {"dst": "default", "dev": "wg-exit", "table": "100"},
            {"dst": "default", "gateway": "203.0.113.1", "dev": "eth0", "table": "main"},
        ]
        with patch.object(checks.killswitch, "run_json_result", return_value=(True, routes)), \
             patch.object(checks.killswitch, "run_cmd", return_value=(0, "-P OUTPUT DROP")):
            r = checks.killswitch.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_nftables_output_drop_is_pass(self):
        routes = [
            {"dst": "default", "dev": "wg-exit", "table": "100"},
            {"dst": "default", "gateway": "203.0.113.1", "dev": "eth0", "table": "main"},
        ]
        nft = {
            "nftables": [
                {
                    "chain": {
                        "family": "inet", "table": "killswitch", "name": "output",
                        "type": "filter", "hook": "output", "policy": "drop",
                    }
                },
                {
                    "rule": {
                        "family": "inet", "table": "killswitch", "chain": "output",
                        "handle": 1, "expr": [{"drop": None}],
                    }
                },
            ]
        }
        # run_json is called for ip rule/route AND nft; distinguish by 'nft' in args
        def rj(args, **kw):
            if "nft" in args:
                return nft
            return routes

        with patch.object(checks.killswitch, "run_json_result", return_value=(True, routes)), \
             patch.object(checks.killswitch, "run_json", side_effect=rj), \
             patch.object(checks.killswitch, "run_cmd", return_value=(-1, "")):
            r = checks.killswitch.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_nft_nested_drop_verdict_is_detected(self):
        self.assertTrue(
            checks.killswitch._rule_verdicts_drop(
                {"expr": [{"verdict": {"kind": "drop"}}]}
            )
        )

    def test_iptables_single_ssh_drop_is_not_general_killswitch(self):
        with patch.object(checks.killswitch.shutil, "which", return_value="/sbin/iptables"), \
             patch.object(
                 checks.killswitch, "run_cmd",
                 return_value=(0, "-A OUTPUT -p tcp --dport 22 -j DROP"),
             ):
            self.assertEqual(len(checks.killswitch._iptables_output()), 1)

    def test_conditional_drop_followed_by_accept_is_not_killswitch(self):
        nft = {
            "nftables": [
                {
                    "chain": {
                        "family": "inet", "table": "filter", "name": "output",
                        "type": "filter", "hook": "output", "policy": "accept",
                    }
                },
                {
                    "rule": {
                        "family": "inet", "table": "filter", "chain": "output",
                        "handle": 2,
                        "expr": [{"drop": None}, {"accept": None}],
                    }
                },
            ]
        }
        with patch.object(checks.killswitch, "run_json_result", return_value=(True, [
            {"dst": "default", "dev": "wg-exit", "table": "100"},
            {"dst": "default", "gateway": "203.0.113.1", "dev": "eth0", "table": "main"},
        ])), patch.object(checks.killswitch, "run_json", return_value=nft), \
             patch.object(checks.killswitch, "run_cmd", return_value=(-1, "")):
            r = checks.killswitch.run(ctx())
        self.assertEqual(r.status, Status.FAIL)

    def test_route_read_failure_is_error(self):
        with patch.object(checks.killswitch, "run_json_result", return_value=(False, [])), \
             patch.object(checks.killswitch, "run_cmd", return_value=(-1, "")):
            r = checks.killswitch.run(ctx())
        self.assertEqual(r.status, Status.ERROR)


class SplitTunnelTest(unittest.TestCase):
    def _patch(self, endpoints, addrs, routes):
        def rj(args, **kw):
            if "addr" in args:
                return True, addrs
            if "route" in args:
                return True, routes
            return True, []

        return (
            patch.object(checks.splittunnel, "run_cmd", return_value=(0, endpoints)),
            patch.object(checks.splittunnel, "run_json_result", side_effect=rj),
        )

    def test_manual_public_route_is_warn(self):
        endpoints = "wg-entry\tKEY\t198.51.100.20:51820\n"
        addrs = [{"ifname": "eth0", "addr_info": [{"local": "203.0.113.153", "prefixlen": 24}]}]
        routes = [{"dst": "198.51.100.0/24", "dev": "eth0", "table": "100"}]
        with self._patch(endpoints, addrs, routes)[0], self._patch(endpoints, addrs, routes)[1]:
            r = checks.splittunnel.run(ctx())
        self.assertEqual(r.status, Status.WARN)
        self.assertIn("198.51.100.0/24", r.summary)
        self.assertEqual(r.details["bypass_route_details"][0]["device"], "eth0")
        self.assertEqual(r.details["bypass_route_details"][0]["table"], "100")

    def test_kernel_and_endpoint_routes_are_pass(self):
        endpoints = "wg-entry\tKEY\t198.51.100.20:51820\n"
        addrs = [{"ifname": "eth0", "addr_info": [{"local": "203.0.113.153", "prefixlen": 24}]}]
        routes = [
            {"dst": "198.51.100.20", "gateway": "203.0.113.1", "dev": "eth0", "table": "100"},
            {"dst": "203.0.113.0/24", "dev": "eth0", "protocol": "kernel"},
        ]
        with self._patch(endpoints, addrs, routes)[0], self._patch(endpoints, addrs, routes)[1]:
            r = checks.splittunnel.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_route_command_failure_is_error(self):
        with patch.object(checks.splittunnel, "run_cmd", return_value=(0, "")), \
             patch.object(checks.splittunnel, "run_json_result", return_value=(False, [])):
            r = checks.splittunnel.run(ctx())
        self.assertEqual(r.status, Status.ERROR)


class WebRtcLocalTest(unittest.TestCase):
    def _addrs(self, addrs):
        return patch.object(checks.webrtclocal, "run_json_result", return_value=(True, addrs))

    def test_public_ip_is_fail(self):
        addrs = [{"ifname": "eth0", "addr_info": [{"local": "203.0.113.153"}]}]
        with self._addrs(addrs):
            r = checks.webrtclocal.run(ctx())
        self.assertEqual(r.status, Status.FAIL)

    def test_private_ip_is_warn(self):
        addrs = [{"ifname": "eth0", "addr_info": [{"local": "192.168.1.5"}]}]
        with self._addrs(addrs):
            r = checks.webrtclocal.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_nothing_is_pass(self):
        with self._addrs([]):
            r = checks.webrtclocal.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_command_failure_is_error(self):
        with patch.object(checks.webrtclocal, "run_json_result", return_value=(False, [])):
            r = checks.webrtclocal.run(ctx())
        self.assertEqual(r.status, Status.ERROR)

    def test_uppercase_tunnel_address_is_ignored(self):
        addrs = [{"ifname": "WG-EXIT", "addr_info": [{"local": "203.0.113.153"}]}]
        with self._addrs(addrs):
            r = checks.webrtclocal.run(ctx())
        self.assertEqual(r.status, Status.PASS)


class InterfaceTest(unittest.TestCase):
    def _links(self, links):
        return patch.object(checks.interface, "run_json", return_value=links)

    def test_two_layer_mtu_overhead_is_warn(self):
        links = [
            {"ifname": "lo", "mtu": 65536},
            {"ifname": "eth0", "mtu": 1500},
            {"ifname": "wg-exit", "mtu": 1300},
        ]
        with self._links(links):
            r = checks.interface.run(ctx())
        self.assertEqual(r.status, Status.WARN)
        self.assertEqual(r.details["tunnel_overhead"], 200)

    def test_legit_1380_single_hop_is_pass(self):
        # Mullvad-style 1380 (120 B overhead) is one layer, not multihop.
        links = [
            {"ifname": "lo", "mtu": 65536},
            {"ifname": "eth0", "mtu": 1500},
            {"ifname": "wg-exit", "mtu": 1380},
        ]
        with self._links(links):
            r = checks.interface.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_pppoe_underlay_single_hop_is_pass(self):
        links = [
            {"ifname": "lo", "mtu": 65536},
            {"ifname": "eth0", "mtu": 1492},
            {"ifname": "wg-exit", "mtu": 1412},
        ]
        with self._links(links):
            r = checks.interface.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_small_mtu_delta_is_pass(self):
        links = [
            {"ifname": "lo", "mtu": 65536},
            {"ifname": "eth0", "mtu": 1500},
            {"ifname": "wg-exit", "mtu": 1460},
        ]
        with self._links(links):
            r = checks.interface.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_no_tunnel_is_warn(self):
        links = [
            {"ifname": "lo", "mtu": 65536},
            {"ifname": "eth0", "mtu": 1500},
        ]
        with self._links(links):
            r = checks.interface.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_uppercase_tunnel_name_is_detected(self):
        links = [{"ifname": "ETH0", "mtu": 1500}, {"ifname": "WG-EXIT", "mtu": 1380}]
        with self._links(links):
            r = checks.interface.run(ctx())
        self.assertEqual(r.status, Status.PASS)


class TcpTimestampTest(unittest.TestCase):
    def test_enabled_is_warn(self):
        with patch.object(
            checks.tcptimestamp,
            "subprocess",
            **{"run.return_value": fake_proc(stdout="1")},
        ):
            r = checks.tcptimestamp.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_disabled_is_pass(self):
        with patch.object(
            checks.tcptimestamp,
            "subprocess",
            **{"run.return_value": fake_proc(stdout="0")},
        ):
            r = checks.tcptimestamp.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_sysctl_failure_is_error_even_with_stdout(self):
        with patch.object(
            checks.tcptimestamp,
            "_sysctl",
            side_effect=[(1, "1"), (1, "1")],
        ):
            r = checks.tcptimestamp.run(ctx())
        self.assertEqual(r.status, Status.ERROR)


class MdnsTest(unittest.TestCase):
    def test_enabled_is_warn(self):
        with patch.object(checks.mdns, "_read", return_value="hosts: files mdns4_minimal\n"), \
             patch.object(checks.mdns, "_listeners", return_value=(True, ["udp *:5353"])):
            r = checks.mdns.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_disabled_is_pass(self):
        with patch.object(checks.mdns, "_read", return_value="hosts: files dns\n"), \
             patch.object(checks.mdns, "_listeners", return_value=(True, [])):
            r = checks.mdns.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_listener_read_failure_is_error(self):
        with patch.object(checks.mdns, "_read", return_value="hosts: files dns\n"), \
             patch.object(checks.mdns, "_listeners", return_value=(False, [])):
            r = checks.mdns.run(ctx())
        self.assertEqual(r.status, Status.ERROR)

    def test_commented_mdns_configuration_is_ignored(self):
        with patch.object(checks.mdns, "_read", return_value="# hosts: files mdns4_minimal\n"), \
             patch.object(checks.mdns, "_listeners", return_value=(True, [])):
            r = checks.mdns.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_resolved_mode_is_warn(self):
        with patch.object(
            checks.mdns, "_read",
            side_effect=["hosts: files dns\n", "MulticastDNS=resolve\n"],
        ), patch.object(checks.mdns, "_listeners", return_value=(True, [])):
            r = checks.mdns.run(ctx())
        self.assertEqual(r.status, Status.WARN)


class DnsTest(unittest.TestCase):
    def setUp(self):
        # Keep unit tests offline: ASN lookup is exercised by its own tests.
        p = patch.object(checks.dns, "asn_lookup", return_value=None)
        p.start()
        self.addCleanup(p.stop)

    def test_public_nameserver_is_fail(self):
        with patch.object(checks.dns, "system_nameservers", return_value=["8.8.8.8"]), \
             patch.object(checks.dns, "resolve_a", return_value=["8.8.8.8"]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.FAIL)

    def test_private_nameserver_is_pass(self):
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", return_value=["203.0.113.20"]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_unresponsive_private_nameserver_is_error(self):
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", return_value=[]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.ERROR)

    def test_multiple_distinct_resolvers_is_fail(self):
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", side_effect=[["8.8.8.8"], ["1.1.1.1"]]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.FAIL)

    def test_expected_dns_mismatch_is_fail(self):
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", return_value=["8.8.8.8"]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"):
            r = checks.dns.run(ctx(expect_dns=["1.1.1.1"]))
        self.assertEqual(r.status, Status.FAIL)

    def test_public_resolver_different_provider_is_warn(self):
        # A public, non-well-known resolver outside the egress /24 -> needs review.
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", return_value=["192.0.2.55"]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_known_public_resolver_is_fail(self):
        # 8.8.8.8 behind a tunnel stub means DNS is leaving to Google -> leak.
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", return_value=["8.8.8.8"]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.FAIL)
        self.assertIn("8.8.8.8", r.details["third_party_resolvers"])

    def test_same_neighborhood_resolvers_not_multiple(self):
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", side_effect=[["203.0.113.20"], ["203.0.113.21"]]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_same_asn_far_block_resolver_is_pass(self):
        # Same provider, different /24s (the old /16 guess was right by luck;
        # a /24 rule alone would have flagged this as a different provider).
        def asn(ip, timeout=5, server=None):
            return 64500 if ip in ("198.51.101.10", "198.51.100.20") else None
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", return_value=["198.51.100.20"]), \
             patch.object(checks.dns, "http_get_text", return_value="198.51.101.10"), \
             patch.object(checks.dns, "asn_lookup", side_effect=asn):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.PASS)
        self.assertTrue(r.details["same_provider_resolver"])

    def test_same_slash24_different_asn_is_warn(self):
        # Proximity lies: same /24, different providers -> must warn.
        def asn(ip, timeout=5, server=None):
            return {"203.0.113.10": 64500, "203.0.113.20": 64501}.get(ip)
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", return_value=["203.0.113.20"]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.dns, "asn_lookup", side_effect=asn):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.WARN)
        self.assertIn("203.0.113.20", r.details["off_provider_resolvers"])

    def test_two_providers_inside_one_slash16_is_fail(self):
        def asn(ip, timeout=5, server=None):
            return {"198.51.100.20": 64500, "198.51.100.21": 64501}.get(ip)
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", side_effect=[["198.51.100.20"], ["198.51.100.21"]]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.dns, "asn_lookup", side_effect=asn):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.FAIL)
        self.assertIn("multiple distinct", r.summary)

    def test_cloudflare_warp_resolver_is_not_third_party(self):
        # Egress and 1.1.1.1 both AS13335 (WARP) -> the tunnel's own resolver.
        def asn(ip, timeout=5, server=None):
            return 13335 if ip in ("1.1.1.1", "203.0.113.10") else None
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", return_value=["1.1.1.1"]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.dns, "asn_lookup", side_effect=asn):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.PASS)
        self.assertEqual(r.details["third_party_resolvers"], [])

    def test_one_off_provider_resolver_is_not_hidden(self):
        # One same-provider and one foreign resolver must still warn.
        def asn(ip, timeout=5, server=None):
            return {"203.0.113.10": 64500, "198.51.100.20": 64500, "192.0.2.30": 64502}.get(ip)
        with patch.object(checks.dns, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.dns, "resolve_a", side_effect=[["198.51.100.20"], ["192.0.2.30"]]), \
             patch.object(checks.dns, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.dns, "asn_lookup", side_effect=asn):
            r = checks.dns.run(ctx())
        self.assertEqual(r.status, Status.FAIL)
        self.assertEqual(r.details["off_provider_resolvers"], ["192.0.2.30"])


class IpTest(unittest.TestCase):
    def test_multiple_ipv4_is_fail(self):
        responses = {
            "https://api.ipify.org": "203.0.113.10",
            "https://ifconfig.me/ip": "1.1.1.1",
        }
        with patch.object(checks.ip, "http_get_text", side_effect=lambda u, t=8: responses.get(u)), \
             patch.object(checks.ip, "http_get_json", return_value=None), \
             patch.object(checks.ip, "_global_ipv6_addresses", return_value=[]):
            r = checks.ip.run(ctx())
        self.assertEqual(r.status, Status.FAIL)

    def test_expected_ip_mismatch_is_fail(self):
        responses = {
            "https://api.ipify.org": "203.0.113.10",
            "https://ifconfig.me/ip": "203.0.113.10",
            "https://ipinfo.io/ip": "203.0.113.10",
            "https://icanhazip.com": "203.0.113.10",
        }
        with patch.object(checks.ip, "http_get_text", side_effect=lambda u, t=8: responses.get(u)), \
             patch.object(checks.ip, "http_get_json", return_value=None), \
             patch.object(checks.ip, "_global_ipv6_addresses", return_value=[]):
            r = checks.ip.run(ctx(expect_ip="1.2.3.4"))
        self.assertEqual(r.status, Status.FAIL)

    def test_consistent_ip_is_pass(self):
        responses = {
            "https://api.ipify.org": "203.0.113.10",
            "https://ifconfig.me/ip": "203.0.113.10",
            "https://ipinfo.io/ip": "203.0.113.10",
            "https://icanhazip.com": "203.0.113.10",
        }
        with patch.object(checks.ip, "http_get_text", side_effect=lambda u, t=8: responses.get(u)), \
             patch.object(checks.ip, "http_get_json", return_value=None), \
             patch.object(checks.ip, "_global_ipv6_addresses", return_value=[]):
            r = checks.ip.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_ipv6_leak_is_fail(self):
        responses = {
            "https://api.ipify.org": "203.0.113.10",
            "https://ifconfig.me/ip": "203.0.113.10",
            "https://ipinfo.io/ip": "203.0.113.10",
            "https://icanhazip.com": "203.0.113.10",
            "https://v6.ident.me": "2001:db8::1",
            "https://ipv6.icanhazip.com": "2001:db8::1",
        }
        with patch.object(checks.ip, "http_get_text", side_effect=lambda u, t=8: responses.get(u)), \
             patch.object(checks.ip, "http_get_json", return_value=None), \
             patch.object(checks.ip, "_global_ipv6_addresses", return_value=[]):
            r = checks.ip.run(ctx())
        self.assertEqual(r.status, Status.FAIL)

    def test_global_ipv6_only_is_warn(self):
        responses = {
            "https://api.ipify.org": "203.0.113.10",
            "https://ifconfig.me/ip": "203.0.113.10",
            "https://ipinfo.io/ip": "203.0.113.10",
            "https://icanhazip.com": "203.0.113.10",
        }
        with patch.object(checks.ip, "http_get_text", side_effect=lambda u, t=8: responses.get(u)), \
             patch.object(checks.ip, "http_get_json", return_value=None), \
             patch.object(checks.ip, "_global_ipv6_addresses", return_value=["2001:db8::1"]):
            r = checks.ip.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_mullvad_exit_false_is_fail(self):
        responses = {
            "https://api.ipify.org": "203.0.113.10",
            "https://ifconfig.me/ip": "203.0.113.10",
            "https://ipinfo.io/ip": "203.0.113.10",
            "https://icanhazip.com": "203.0.113.10",
        }
        with patch.object(checks.ip, "http_get_text", side_effect=lambda u, t=8: responses.get(u)), \
             patch.object(checks.ip, "http_get_json", return_value={"mullvad_exit_ip": False, "ip": "203.0.113.10"}), \
             patch.object(checks.ip, "_global_ipv6_addresses", return_value=[]):
            r = checks.ip.run(ctx(expect_mullvad=True))
        self.assertEqual(r.status, Status.FAIL)

    def test_mullvad_exit_false_without_expect_is_pass(self):
        responses = {
            "https://api.ipify.org": "203.0.113.10",
            "https://ifconfig.me/ip": "203.0.113.10",
            "https://ipinfo.io/ip": "203.0.113.10",
            "https://icanhazip.com": "203.0.113.10",
        }
        with patch.object(checks.ip, "http_get_text", side_effect=lambda u, t=8: responses.get(u)), \
             patch.object(checks.ip, "http_get_json", return_value={"mullvad_exit_ip": False, "ip": "203.0.113.10"}), \
             patch.object(checks.ip, "_global_ipv6_addresses", return_value=[]):
            r = checks.ip.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_ipv6_expected_match_is_pass(self):
        responses = {
            "https://api.ipify.org": "203.0.113.10",
            "https://ifconfig.me/ip": "203.0.113.10",
            "https://ipinfo.io/ip": "203.0.113.10",
            "https://icanhazip.com": "203.0.113.10",
            "https://v6.ident.me": "2001:db8::1",
            "https://ipv6.icanhazip.com": "2001:db8::1",
        }
        with patch.object(checks.ip, "http_get_text", side_effect=lambda u, t=8: responses.get(u)), \
             patch.object(checks.ip, "http_get_json", return_value=None), \
             patch.object(checks.ip, "_global_ipv6_addresses", return_value=[]):
            r = checks.ip.run(ctx(expect_ip="2001:db8::1"))
        self.assertEqual(r.status, Status.PASS)

    def test_ipv6_expected_mismatch_is_fail(self):
        responses = {
            "https://api.ipify.org": "203.0.113.10",
            "https://ifconfig.me/ip": "203.0.113.10",
            "https://ipinfo.io/ip": "203.0.113.10",
            "https://icanhazip.com": "203.0.113.10",
            "https://v6.ident.me": "2001:db8::1",
            "https://ipv6.icanhazip.com": "2001:db8::1",
        }
        with patch.object(checks.ip, "http_get_text", side_effect=lambda u, t=8: responses.get(u)), \
             patch.object(checks.ip, "http_get_json", return_value=None), \
             patch.object(checks.ip, "_global_ipv6_addresses", return_value=[]):
            r = checks.ip.run(ctx(expect_ip="2001:db8::2"))
        self.assertEqual(r.status, Status.FAIL)


class QuicTest(unittest.TestCase):
    def test_udp_differs_from_http_is_fail(self):
        with patch.object(checks.quic, "stun_mapped_address", return_value=("1.1.1.1", 1, "m")), \
             patch.object(checks.quic, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.quic, "_resolve_ipv4", return_value="9.9.9.9"), \
             patch.object(checks.quic, "quic_probe", return_value="timeout"):
            r = checks.quic.run(ctx())
        self.assertEqual(r.status, Status.FAIL)

    def test_udp_matches_http_is_pass_even_if_probe_times_out(self):
        with patch.object(checks.quic, "stun_mapped_address", return_value=("203.0.113.10", 1, "m")), \
             patch.object(checks.quic, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.quic, "_resolve_ipv4", return_value="9.9.9.9"), \
             patch.object(checks.quic, "quic_probe", return_value="timeout"):
            r = checks.quic.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_stun_failed_is_warn(self):
        with patch.object(checks.quic, "stun_mapped_address", return_value=(None, None, None)), \
             patch.object(checks.quic, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.quic, "_resolve_ipv4", return_value="9.9.9.9"), \
             patch.object(checks.quic, "quic_probe", return_value="timeout"):
            r = checks.quic.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_invalid_quic_response_is_not_reachable(self):
        response = b"\xc0" + b"\x00" * 20
        self.assertFalse(checks.quic._is_version_negotiation(response, b"a" * 8, b"b" * 8))

    def test_udp_ipv6_vs_http_ipv4_is_not_fail(self):
        with patch.object(checks.quic, "stun_mapped_address", return_value=("2001:db8::1", 1, "m")), \
             patch.object(checks.quic, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.quic, "_resolve_ipv4", return_value="9.9.9.9"), \
             patch.object(checks.quic, "quic_probe", return_value="timeout"):
            r = checks.quic.run(ctx())
        self.assertEqual(r.status, Status.WARN)


class WebrtcTest(unittest.TestCase):
    def _stun(self, results):
        return patch.object(
            checks.webrtc,
            "stun_mapped_address",
            side_effect=lambda srv, port, timeout=5: results.get(srv, (None, None, None)),
        )

    def test_no_stun_is_error(self):
        with self._stun({}), patch.object(checks.webrtc, "http_get_text", return_value="203.0.113.10"):
            r = checks.webrtc.run(ctx())
        self.assertEqual(r.status, Status.ERROR)

    def test_multiple_distinct_udp_is_fail(self):
        results = {
            "stun.l.google.com": ("203.0.113.10", 1, "m"),
            "stun1.l.google.com": ("1.1.1.1", 1, "m"),
        }
        with self._stun(results), patch.object(checks.webrtc, "http_get_text", return_value="203.0.113.10"):
            r = checks.webrtc.run(ctx())
        self.assertEqual(r.status, Status.FAIL)

    def test_udp_differs_http_is_fail(self):
        results = {
            "stun.l.google.com": ("1.1.1.1", 1, "m"),
            "stun1.l.google.com": ("1.1.1.1", 1, "m"),
        }
        with self._stun(results), patch.object(checks.webrtc, "http_get_text", return_value="203.0.113.10"):
            r = checks.webrtc.run(ctx())
        self.assertEqual(r.status, Status.FAIL)

    def test_udp_ipv6_vs_http_ipv4_is_not_fail(self):
        results = {
            "stun.l.google.com": ("2001:db8::1", 1, "m"),
            "stun1.l.google.com": ("2001:db8::1", 1, "m"),
        }
        with self._stun(results), patch.object(checks.webrtc, "http_get_text", return_value="203.0.113.10"):
            r = checks.webrtc.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_private_udp_is_warn(self):
        results = {"stun.l.google.com": ("192.168.1.5", 1, "m")}
        with self._stun(results), patch.object(checks.webrtc, "http_get_text", return_value="203.0.113.10"):
            r = checks.webrtc.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_consistent_is_pass(self):
        results = {
            "stun.l.google.com": ("203.0.113.10", 1, "m"),
            "stun1.l.google.com": ("203.0.113.10", 1, "m"),
        }
        with self._stun(results), patch.object(checks.webrtc, "http_get_text", return_value="203.0.113.10"):
            r = checks.webrtc.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_public_udp_without_http_egress_is_warn(self):
        with patch.object(
            checks.webrtc,
            "parallel_map",
            return_value=[("203.0.113.10", 1234, "xor-mapped")],
        ), patch.object(checks.webrtc, "http_get_text", return_value=None):
            r = checks.webrtc.run(ctx())
        self.assertEqual(r.status, Status.WARN)


class EcsTest(unittest.TestCase):
    def setUp(self):
        p = patch.object(checks.ecs, "asn_lookup", return_value=None)
        p.start()
        self.addCleanup(p.stop)

    # Distinct /24s: egress 203.0.113.0/24, resolver 198.51.100.0/24.
    def test_no_answer_is_skip(self):
        with patch.object(checks.ecs, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.ecs, "resolver_ips", return_value=["198.51.100.20"]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.ecs, "dns_query", side_effect=[[], []]):
            r = checks.ecs.run(ctx())
        self.assertEqual(r.status, Status.SKIP)

    def test_no_nameservers_is_skip(self):
        with patch.object(checks.ecs, "system_nameservers", return_value=[]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"):
            r = checks.ecs.run(ctx())
        self.assertEqual(r.status, Status.SKIP)

    def test_disclosed_outside_resolver_and_egress_is_warn(self):
        with patch.object(checks.ecs, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.ecs, "resolver_ips", return_value=["198.51.100.20"]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.ecs, "dns_query", side_effect=[[{"value": "8.8.8.8"}], [{"value": "8.8.8.8"}]]):
            r = checks.ecs.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_same_slash16_but_other_slash24_is_warn(self):
        # Disclosed subnet shares the resolver's /16 but not its /24 -> flagged.
        with patch.object(checks.ecs, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.ecs, "resolver_ips", return_value=["198.51.100.20"]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.ecs, "dns_query", side_effect=[[{"value": "198.51.101.0"}], []]):
            r = checks.ecs.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_edns_subnet_label_is_parsed_not_treated_as_ip(self):
        with patch.object(checks.ecs, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.ecs, "resolver_ips", return_value=["198.51.100.20"]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.ecs, "dns_query", side_effect=[[{"value": "edns0-client-subnet 203.0.113.0/24"}], [{"value": "edns0-client-subnet 203.0.113.0/24"}]]):
            r = checks.ecs.run(ctx())
        self.assertIn("203.0.113.0", r.details["baseline"])
        self.assertNotIn("edns0-client-subnet", r.details["baseline"])
        self.assertEqual(r.status, Status.WARN)  # forwarding the injected ECS

    def test_forwards_ecs_is_warn(self):
        with patch.object(checks.ecs, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.ecs, "resolver_ips", return_value=["198.51.100.20"]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.ecs, "dns_query", side_effect=[[{"value": "198.51.100.20"}], [{"value": "203.0.113.10"}]]):
            r = checks.ecs.run(ctx())
        self.assertEqual(r.status, Status.WARN)
        self.assertTrue(r.details["forwards_ecs"])

    def test_no_leak_is_pass(self):
        with patch.object(checks.ecs, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.ecs, "resolver_ips", return_value=["198.51.100.20"]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.ecs, "dns_query", side_effect=[[{"value": "198.51.100.20"}], [{"value": "198.51.100.20"}]]):
            r = checks.ecs.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_same_asn_other_slash24_is_pass(self):
        # Disclosed subnet in another /24 of the resolver's provider -> normal.
        def asn(ip, timeout=5, server=None):
            return {"198.51.100.20": 64500, "198.51.101.0": 64500}.get(ip)
        with patch.object(checks.ecs, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.ecs, "resolver_ips", return_value=["198.51.100.20"]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.ecs, "dns_query", side_effect=[[{"value": "198.51.101.0"}], []]), \
             patch.object(checks.ecs, "asn_lookup", side_effect=asn):
            r = checks.ecs.run(ctx())
        self.assertEqual(r.status, Status.PASS)

    def test_same_slash16_different_provider_is_warn(self):
        # Same /16, different ASN -> a real third-party subnet leak.
        def asn(ip, timeout=5, server=None):
            return {"198.51.100.20": 64500, "198.51.101.0": 64501}.get(ip)
        with patch.object(checks.ecs, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.ecs, "resolver_ips", return_value=["198.51.100.20"]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.ecs, "dns_query", side_effect=[[{"value": "198.51.101.0"}], []]), \
             patch.object(checks.ecs, "asn_lookup", side_effect=asn):
            r = checks.ecs.run(ctx())
        self.assertEqual(r.status, Status.WARN)

    def test_same_slash24_resolver_own_ip_is_not_forwarding(self):
        # Live false positive: resolver and egress share a /24, baseline and
        # active both return the resolver's own bare IP -> no ECS was forwarded.
        with patch.object(checks.ecs, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.ecs, "resolver_ips", return_value=["203.0.113.20"]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.ecs, "dns_query", side_effect=[[{"value": "203.0.113.20"}], [{"value": "203.0.113.20"}]]):
            r = checks.ecs.run(ctx())
        self.assertEqual(r.status, Status.PASS)
        self.assertFalse(r.details["forwards_ecs"])

    def test_same_slash24_different_provider_is_warn(self):
        # Prefix proximity (/24) no longer masks a different provider.
        def asn(ip, timeout=5, server=None):
            return {
                "203.0.113.10": 64502, "203.0.113.20": 64500,
                "203.0.113.30": 64501,
            }.get(ip)
        with patch.object(checks.ecs, "system_nameservers", return_value=["10.64.0.1"]), \
             patch.object(checks.ecs, "resolver_ips", return_value=["203.0.113.20"]), \
             patch.object(checks.ecs, "http_get_text", return_value="203.0.113.10"), \
             patch.object(checks.ecs, "dns_query", side_effect=[[{"value": "203.0.113.30"}], []]), \
             patch.object(checks.ecs, "asn_lookup", side_effect=asn):
            r = checks.ecs.run(ctx())
        self.assertEqual(r.status, Status.WARN)


class SplitTunnelPublicTest(unittest.TestCase):
    def test_cgnat_is_not_public(self):
        self.assertFalse(checks.splittunnel._is_public("100.64.0.0/10"))
        self.assertFalse(checks.splittunnel._is_public("100.64.1.5"))

    def test_real_public_is_public(self):
        self.assertTrue(checks.splittunnel._is_public("8.8.8.8/32"))
        self.assertTrue(checks.splittunnel._is_public("198.51.100.0/24"))

    def test_ipv6_routes_do_not_raise(self):
        # Documentation ranges are treated as public (see DOCUMENTATION_NETWORKS).
        self.assertTrue(checks.splittunnel._is_public("2001:db8::/48"))
        self.assertTrue(checks.splittunnel._is_public("2001:db8::/32"))
        self.assertFalse(checks.splittunnel._is_public("fe80::/10"))
        self.assertFalse(checks.splittunnel._is_public("::1/128"))


class RunChecksValidationTest(unittest.TestCase):
    def test_unknown_only_raises(self):
        with self.assertRaises(ValueError):
            core.run_checks(ctx(), only=["doesnotexist"])

    def test_unknown_exclude_raises(self):
        with self.assertRaises(ValueError):
            core.run_checks(ctx(), exclude=["nope"])

    def test_mixed_known_and_unknown_raises(self):
        with self.assertRaises(ValueError):
            core.run_checks(ctx(), only=["ip", "dns", "bogus"])

    def test_unknown_status_is_error(self):
        from leakkeeper.result import CheckResult

        self.assertEqual(
            core.overall_status([CheckResult("x", "x", "x", status="bogus")]),
            Status.ERROR,
        )


class StunParseTest(unittest.TestCase):
    def _binding_response(self, body: bytes, txid: int) -> bytes:
        import struct

        from leakkeeper.netutil import MAGIC_COOKIE
        header = struct.pack(">HHI", 0x0101, len(body), MAGIC_COOKIE) + txid.to_bytes(12, "big")
        return header + body

    def test_ipv6_xor_mapped(self):
        import struct

        from leakkeeper.netutil import MAGIC_COOKIE, _parse_stun_response
        txid = 0x00112233445566778899AABB
        xaddr = 0x20010DB8000000000000000000000001 ^ ((MAGIC_COOKIE << 96) | txid)
        xport = 54321 ^ (MAGIC_COOKIE >> 16)
        value = b"\x00\x02" + struct.pack(">H", xport) + xaddr.to_bytes(16, "big")
        attr = struct.pack(">HH", 0x0020, len(value)) + value
        body = attr + b"\x00" * ((-len(attr)) % 4)
        ip, port, method = _parse_stun_response(self._binding_response(body, txid), txid)
        self.assertEqual(ip, "2001:db8::1")
        self.assertEqual(port, 54321)
        self.assertEqual(method, "xor-mapped")

    def test_ipv4_xor_mapped(self):
        import struct

        from leakkeeper.netutil import MAGIC_COOKIE, _parse_stun_response
        txid = 0x00112233445566778899AABB
        xaddr = 0xCB00710A ^ MAGIC_COOKIE  # 203.0.113.10
        xport = 40000 ^ (MAGIC_COOKIE >> 16)
        value = b"\x00\x01" + struct.pack(">H", xport) + struct.pack(">I", xaddr)
        attr = struct.pack(">HH", 0x0020, len(value)) + value
        body = attr + b"\x00" * ((-len(attr)) % 4)
        ip, port, method = _parse_stun_response(self._binding_response(body, txid), txid)
        self.assertEqual(ip, "203.0.113.10")
        self.assertEqual(port, 40000)
        self.assertEqual(method, "xor-mapped")

    def test_not_binding_success_returns_none(self):
        from leakkeeper.netutil import _parse_stun_response
        self.assertEqual(_parse_stun_response(b"\x01\x11" + b"\x00" * 18, 0), (None, None, None))

    def test_truncated_attribute_returns_none(self):
        import struct

        from leakkeeper.netutil import MAGIC_COOKIE, _parse_stun_response
        hdr = struct.pack(">HHI", 0x0101, 6, MAGIC_COOKIE) + (0).to_bytes(12, "big")
        body = struct.pack(">HH", 0x0020, 8) + b"\x00\x01"  # claims 8 bytes, has 2
        self.assertEqual(_parse_stun_response(hdr + body, 0), (None, None, None))

    def test_mismatched_txid_returns_none(self):
        import struct

        from leakkeeper.netutil import MAGIC_COOKIE, _parse_stun_response
        sent = 0x00112233445566778899AABB
        received = 0xDEADBEEFDEADBEEFDEADBEEF
        body = struct.pack(">HH", 0x0020, 8) + b"\x00\x01\xb9\xd5\x9a\xf2"
        hdr = struct.pack(">HHI", 0x0101, len(body), MAGIC_COOKIE) + received.to_bytes(12, "big")
        self.assertEqual(_parse_stun_response(hdr + body, sent), (None, None, None))


class BuildQueryTest(unittest.TestCase):
    def test_invalid_ecs_yields_no_additional_record(self):
        import struct

        from leakkeeper.netutil import _build_query
        q = _build_query("example.com", 16, ecs="not-an-ip")
        self.assertEqual(struct.unpack(">H", q[10:12])[0], 0)

    def test_valid_ecs_yields_one_additional_record(self):
        import struct

        from leakkeeper.netutil import _build_query
        q = _build_query("example.com", 16, ecs="203.0.113.10")
        self.assertEqual(struct.unpack(">H", q[10:12])[0], 1)
        additional = 12 + len(b"\x07example\x03com\x00") + 4
        # OPT RR: root name, type/class/TTL, then the 7-byte ECS option.
        self.assertEqual(struct.unpack(">H", q[additional + 9 : additional + 11])[0], 11)
        self.assertEqual(struct.unpack(">H", q[additional + 13 : additional + 15])[0], 7)


if __name__ == "__main__":
    unittest.main()
