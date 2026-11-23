#!/usr/bin/env python3
"""Unit tests for Kerio Control integration: logtest parser and ossec.conf editing.

    python3 -m unittest discover -s tests -p 'test_*.py' -v
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "lib"))

import ossec_remote  # noqa: E402
import run_logtest  # noqa: E402

FIXTURE_CONF = os.path.join(HERE, "fixtures", "ossec.conf.sample")
KERIO_IP, LISTEN_IP = "192.0.2.1", "192.0.2.10"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class ParserTest(unittest.TestCase):
    def setUp(self):
        self.results = run_logtest.parse_output(read(os.path.join(HERE, "fixtures", "logtest_output_sample.txt")))

    def test_event_count(self):
        self.assertEqual(len(self.results), 3)

    def test_ips_blacklist_event(self):
        r = self.results[0]
        self.assertEqual(r["decoder"], "kerio-control")
        self.assertEqual(r["rule_id"], "100803")
        self.assertEqual(r["level"], 6)
        self.assertTrue(r["alert"])
        self.assertEqual(r["fields"]["srcip"], "192.0.2.100")
        self.assertEqual(r["fields"]["dstip"], "198.51.100.102")
        self.assertEqual(r["fields"]["kerio.action"], "Packet drop")
        self.assertEqual(r["fields"]["kerio.severity"], "Blacklist")
        self.assertEqual(r["fields"]["kerio.rule_id"], "1:2400033")

    def test_anti_hammering_event(self):
        r = self.results[1]
        self.assertEqual(r["decoder"], "kerio-control")
        self.assertEqual(r["rule_id"], "100804")
        self.assertEqual(r["level"], 12)
        self.assertTrue(r["alert"])
        self.assertEqual(r["fields"]["srcip"], "198.51.100.25")

    def test_no_decoder(self):
        r = self.results[2]
        self.assertIsNone(r["decoder"])
        self.assertIsNone(r["rule_id"])

    def test_check(self):
        self.assertEqual(run_logtest.check(self.results[0], {"rule_id": "100803", "level": 6}), [])
        self.assertTrue(run_logtest.check(self.results[0], {"rule_id": "100800"}))
        self.assertEqual(run_logtest.check(self.results[2], {"decoder_not": "kerio-control"}), [])


class OssecRemoteTest(unittest.TestCase):
    def setUp(self):
        self.text = read(FIXTURE_CONF)

    def test_conflict_detected_for_udp_514(self):
        found = ossec_remote.conflicts(self.text, 514, "udp")
        self.assertEqual(len(found), 1)

    def test_no_conflict_with_ksc_tcp_514(self):
        # KSC uses TCP 514; requesting UDP 514 without the unmanaged UDP block should find only the UDP block
        text_without_udp = self.text.replace(ossec_remote.conflicts(self.text, 514, "udp")[0]["text"], "")
        self.assertEqual(ossec_remote.conflicts(text_without_udp, 514, "udp"), [])

    def test_render_refuses_without_adopt_when_unmanaged_udp_exists(self):
        new, found = ossec_remote.render(self.text, 514, "udp", KERIO_IP, LISTEN_IP, adopt=False)
        self.assertIsNone(new)
        self.assertEqual(len(found), 1)

    def test_adopt_replaces_unmanaged_block_and_keeps_ksc(self):
        new, _ = ossec_remote.render(self.text, 514, "udp", KERIO_IP, LISTEN_IP, adopt=True)
        # Check Kerio managed block is present
        self.assertEqual(new.count(ossec_remote.BEGIN), 1)
        self.assertIn("<protocol>udp</protocol>", new)
        self.assertIn(f"<allowed-ips>{KERIO_IP}/32</allowed-ips>", new)
        # Check KSC TCP 514 block is still intact!
        self.assertIn("<protocol>tcp</protocol>", new)
        self.assertIn("<allowed-ips>192.0.2.5/32</allowed-ips>", new)
        # Check Agent 1514 block is still intact
        self.assertIn("<port>1514</port>", new)
        self.assertEqual(ossec_remote.conflicts(new, 514, "udp"), [])

    def test_render_cidr(self):
        new, _ = ossec_remote.render(self.text, 514, "udp", "192.0.2.0/24", LISTEN_IP, adopt=True)
        self.assertIn("<allowed-ips>192.0.2.0/24</allowed-ips>", new)

    def test_idempotent(self):
        once, _ = ossec_remote.render(self.text, 514, "udp", KERIO_IP, LISTEN_IP, adopt=True)
        twice, found = ossec_remote.render(once, 514, "udp", KERIO_IP, LISTEN_IP, adopt=False)
        self.assertEqual(found, [])
        self.assertEqual(once, twice)

    def test_update_changes_only_managed_block(self):
        once, _ = ossec_remote.render(self.text, 514, "udp", KERIO_IP, LISTEN_IP, adopt=True)
        changed, _ = ossec_remote.render(once, 514, "udp", "192.0.2.250", LISTEN_IP, adopt=False)
        self.assertIn("<allowed-ips>192.0.2.250/32</allowed-ips>", changed)
        self.assertEqual(changed.count(ossec_remote.BEGIN), 1)

    def test_remove_restores_clean_config(self):
        rendered, _ = ossec_remote.render(self.text, 514, "udp", KERIO_IP, LISTEN_IP, adopt=True)
        cleaned, removed = ossec_remote.remove(rendered)
        self.assertTrue(removed)
        self.assertNotIn(ossec_remote.BEGIN, cleaned)
        # KSC and agents still present
        self.assertIn("<allowed-ips>192.0.2.5/32</allowed-ips>", cleaned)
        self.assertIn("<port>1514</port>", cleaned)


if __name__ == "__main__":
    unittest.main()
