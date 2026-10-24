#!/usr/bin/env python3
"""V0.8 offline comparison of two validated nftables forward-chain snapshots.

This program DOES NOT execute nftables, access network namespaces, or infer
ALLOW/DENY from counters alone. Both inputs are saved JSON snapshots from
`nft -j list chain inet ztlab_v04 forward` in the *same deployment*.
"""

import argparse
import copy
import json
import sys
from pathlib import Path

from v08_counter_parser import EXPECTED, fixture, parse

MEASUREMENTS = ("packets", "bytes")


def compare(before_document, after_document, expected_counter=None):
    """Validate both raw policy snapshots and compute monotonic rule deltas."""
    if expected_counter is not None and expected_counter not in EXPECTED:
        raise ValueError(f"Unrecognized expected counter: {expected_counter}")

    before = parse(before_document)
    after = parse(after_document)
    if (before["schema_version"], before["table"], before["chain"]) != (
        after["schema_version"], after["table"], after["chain"]
    ):
        raise ValueError("Snapshot chain identity differs")

    deltas = {}
    for name in EXPECTED:
        b, a = before["counters"][name], after["counters"][name]
        for measure in MEASUREMENTS:
            if a[measure] < b[measure]:
                raise ValueError(
                    f"Counter moved backwards: {name}.{measure}; "
                    "snapshots may come from different deployments"
                )
        deltas[name] = {
            "packets_before": b["packets"],
            "packets_after": a["packets"],
            "packet_delta": a["packets"] - b["packets"],
            "bytes_before": b["bytes"],
            "bytes_after": a["bytes"],
            "byte_delta": a["bytes"] - b["bytes"],
        }

    return {
        "schema_version": "1.0",
        "table": before["table"],
        "chain": before["chain"],
        "expected_counter": expected_counter,
        "expected_counter_packets_increased": (
            deltas[expected_counter]["packet_delta"] > 0
            if expected_counter is not None else None
        ),
        "deltas": deltas,
        "interpretation": (
            "Aggregate rule-counter changes only; an observed behavioral "
            "test result is separately required for any ALLOW/DENY verdict."
        ),
    }


def add_to_counter(document, name, packets, bytes_count):
    """Increment a fixture counter; the parser fixture has known rule order."""
    if name not in EXPECTED:
        raise ValueError(f"Unknown fixture counter: {name}")
    result = copy.deepcopy(document)
    rules = [entry["rule"] for entry in result["nftables"] if "rule" in entry]
    target = rules[list(EXPECTED).index(name)]["expr"][-2]["counter"]
    target["packets"] += packets
    target["bytes"] += bytes_count
    return result


def self_test():
    before = fixture()
    after = add_to_counter(before, "allow_emp_app", 3, 180)
    outcome = compare(before, after, "allow_emp_app")
    assert outcome["expected_counter_packets_increased"] is True
    assert outcome["deltas"]["allow_emp_app"]["packet_delta"] == 3
    assert outcome["deltas"]["allow_emp_app"]["byte_delta"] == 180
    assert outcome["deltas"]["drop"]["packet_delta"] == 0

    # More than one counter can change within a test window; do not infer
    # which single flow caused all changes from aggregate counters.
    noisy_after = add_to_counter(after, "drop", 2, 128)
    noisy = compare(before, noisy_after, "allow_emp_app")
    assert noisy["deltas"]["drop"]["packet_delta"] == 2
    assert noisy["expected_counter_packets_increased"] is True

    unchanged = compare(before, before, "drop")
    assert unchanged["expected_counter_packets_increased"] is False

    negative_cases = []
    wrong_policy = copy.deepcopy(after)
    wrong_policy["nftables"][1]["chain"]["policy"] = "accept"
    negative_cases.append(("wrong_policy", before, wrong_policy, "allow_emp_app"))

    missing_rule = copy.deepcopy(after)
    missing_rule["nftables"].pop()
    negative_cases.append(("missing_rule", before, missing_rule, "allow_emp_app"))

    negative_cases.append(("backward_packets", after, before, "allow_emp_app"))

    backward_bytes = copy.deepcopy(after)
    # Rule allow_emp_app is the second rule in the parser's fixture.
    backward_bytes["nftables"][3]["rule"]["expr"][-2]["counter"]["bytes"] = 1
    negative_cases.append(("backward_bytes", before, backward_bytes, "allow_emp_app"))

    negative_cases.append(("unknown_counter", before, after, "unknown"))

    for label, b, a, target in negative_cases:
        try:
            compare(b, a, target)
        except ValueError:
            continue
        raise AssertionError(f"Unsafe sample accepted: {label}")

    print("V08_COUNTER_DELTA_SELF_TEST=PASS")
    print("EXPECTED_RULE_COUNTERS=4")
    print("POSITIVE_DELTA_CASES=2")
    print("ZERO_DELTA_CASES=1")
    print(f"REJECTED_INVALID_CASES={len(negative_cases)}")
    print("NETWORK_TESTS_EXECUTED=0")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--self-test", action="store_true")
    cli.add_argument("--before", type=Path, help="Saved nftables JSON before test")
    cli.add_argument("--after", type=Path, help="Saved nftables JSON after test")
    cli.add_argument("--expected-counter", choices=tuple(EXPECTED))
    args = cli.parse_args()

    if args.self_test:
        if args.before or args.after or args.expected_counter:
            cli.error("--self-test cannot be combined with snapshot arguments")
        self_test()
        return
    if not args.before or not args.after:
        cli.error("--before and --after are both required")
    before = json.loads(args.before.read_text(encoding="utf-8"))
    after = json.loads(args.after.read_text(encoding="utf-8"))
    print(json.dumps(compare(before, after, args.expected_counter), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, AssertionError) as exc:
        print(f"V08_COUNTER_DELTA_ERROR={exc}", file=sys.stderr)
        sys.exit(1)
