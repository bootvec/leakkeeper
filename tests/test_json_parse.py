"""Integration-style tests using real command output captured from `ip`/`nft`.

These do NOT run the actual binaries — they feed the parsers with real,
captured JSON (tests/fixtures/commands.json) so a change in the parsing logic
is caught without requiring root or a live system. They complement the pure
unit tests, which mock everything.
"""

from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from leakkeeper import checks
from leakkeeper.config import CheckContext
from leakkeeper.result import Status

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "commands.json")


def _load() -> dict:
    with open(FIXTURE, encoding="utf-8") as fh:
        return json.load(fh)


class KillSwitchJsonParseTest(unittest.TestCase):
    def test_nft_drop_policy_and_rule_are_detected(self):
        data = _load()
        routes = [r for r in data["ip_route_all"] if r["dst"] == "default"]

        def rj(args, **kw):
            if "nft" in args:
                return data["nft_ruleset"]
            if "rule" in args:
                return data["ip_rule"]
            return routes

        with patch.object(checks.killswitch, "run_json", side_effect=rj), \
             patch.object(checks.killswitch, "run_cmd", return_value=(-1, "")):
            r = checks.killswitch.run(CheckContext())
        self.assertEqual(r.status, Status.PASS)
        self.assertTrue(r.details["output_drop"])
        self.assertTrue(any("policy" in f for f in r.details["firewall"]))

    def test_nft_accept_policy_no_drop_is_fail(self):
        data = _load()
        ruleset = {
            "nftables": [
                {
                    "chain": {
                        "family": "inet", "table": "ks", "name": "output",
                        "type": "filter", "hook": "output", "policy": "accept",
                    }
                }
            ]
        }
        routes = [r for r in data["ip_route_all"] if r["dst"] == "default"]

        def rj(args, **kw):
            if "nft" in args:
                return ruleset
            if "rule" in args:
                return data["ip_rule"]
            return routes

        with patch.object(checks.killswitch, "run_json", side_effect=rj), \
             patch.object(checks.killswitch, "run_cmd", return_value=(-1, "")):
            r = checks.killswitch.run(CheckContext())
        self.assertEqual(r.status, Status.FAIL)
        self.assertFalse(r.details["output_drop"])


class SplitTunnelJsonParseTest(unittest.TestCase):
    def test_public_route_on_physical_dev_is_warn(self):
        data = _load()

        def rj(args, **kw):
            if "addr" in args:
                return True, data["ip_addr"]
            if "route" in args:
                return True, [r for r in data["ip_route_all"] if r["dst"] != "default"]
            return True, []

        with patch.object(checks.splittunnel, "run_json_result", side_effect=rj), \
             patch.object(checks.splittunnel, "run_cmd", return_value=(0, "wg-entry\tKEY\t198.51.100.20:51820\n")):
            r = checks.splittunnel.run(CheckContext())
        self.assertEqual(r.status, Status.WARN)
        self.assertIn("198.51.100.0/24", r.summary)


class InterfaceJsonParseTest(unittest.TestCase):
    def test_mtu_from_real_link_json(self):
        data = _load()
        with patch.object(checks.interface, "run_json", return_value=data["ip_link"]):
            r = checks.interface.run(CheckContext())
        # 1380 on a 1500 underlay is 120 B of overhead: a legitimate single
        # encapsulation layer, not a multihop fingerprint.
        self.assertEqual(r.status, Status.PASS)


class WebRtcLocalJsonParseTest(unittest.TestCase):
    def test_global_and_private_addrs_parsed(self):
        data = _load()
        with patch.object(checks.webrtclocal, "run_json_result", return_value=(True, data["ip_addr"])):
            r = checks.webrtclocal.run(CheckContext())
        # eth0 has a public IPv4 => FAIL (would leak the real public IP)
        self.assertEqual(r.status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()
