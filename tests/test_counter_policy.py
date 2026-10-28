"""Offline synthetic policy regression tests, never execute nft or ip."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from v08_counter_parser import fixture, parse
from v08_counter_delta import compare, add_to_counter

class CounterPolicyTests(unittest.TestCase):
    def test_valid_policy(self):
        self.assertEqual(len(parse(fixture())["counters"]), 4)

    def test_drop_first_rejected(self):
        doc = fixture()
        doc["nftables"].insert(2, doc["nftables"].pop())
        with self.assertRaises(ValueError):
            parse(doc)

    def test_return_rule_last_rejected(self):
        doc = fixture()
        doc["nftables"][2], doc["nftables"][3] = doc["nftables"][3], doc["nftables"][2]
        with self.assertRaises(ValueError):
            parse(doc)

    def test_wrong_priority_rejected(self):
        doc = fixture()
        doc["nftables"][1]["chain"]["prio"] = 100
        with self.assertRaises(ValueError):
            parse(doc)

    def test_boolean_counter_rejected(self):
        doc = fixture()
        doc["nftables"][2]["rule"]["expr"][-2]["counter"]["packets"] = True
        with self.assertRaises(ValueError):
            parse(doc)

    def test_counter_growth(self):
        before = fixture()
        after = add_to_counter(before, "allow_emp_app", 2, 120)
        self.assertEqual(compare(before, after)["deltas"]["allow_emp_app"]["packet_delta"], 2)

    def test_counter_reset(self):
        before = fixture()
        after = add_to_counter(before, "drop", 1, 60)
        with self.assertRaises(ValueError):
            compare(after, before)

    def test_malformed_document(self):
        for doc in (None, {}, {"nftables": []}):
            with self.subTest(doc=doc), self.assertRaises(ValueError):
                parse(doc)
