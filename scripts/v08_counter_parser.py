#!/usr/bin/env python3
"""V0.8 offline parser for a known, bounded nftables forward chain."""
import argparse
import json
import sys
from pathlib import Path

FAMILY, TABLE, CHAIN = "inet", "ztlab_v04", "forward"

def match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}

def meta(key):
    return {"meta": {"key": key}}

def payload(protocol, field):
    return {"payload": {"protocol": protocol, "field": field}}

def ct_state(value):
    return {
        "match": {
            "op": "in",
            "left": {"ct": {"key": "state"}},
            "right": value,
        }
    }

EXPECTED = {
    "established_related": (
        [ct_state(["established", "related"])], "accept"),
    "allow_emp_app": (
        [match(meta("iifname"), "gw-emp"),
         match(meta("oifname"), "gw-app"),
         match(payload("ip", "saddr"), "10.200.10.2"),
         match(payload("ip", "daddr"), "10.200.20.2"),
         match(payload("tcp", "dport"), 8080), ct_state("new")], "accept"),
    "allow_app_data": (
        [match(meta("iifname"), "gw-app"),
         match(meta("oifname"), "gw-data"),
         match(payload("ip", "saddr"), "10.200.20.2"),
         match(payload("ip", "daddr"), "10.200.30.2"),
         match(payload("tcp", "dport"), 5432), ct_state("new")], "accept"),
    "drop": ([], "drop"),
}

def normalized(expr):
    if (isinstance(expr, dict) and isinstance(expr.get("match"), dict)
            and expr["match"].get("left") == {"ct": {"key": "state"}}):
        value = expr["match"].get("right")
        if isinstance(value, dict) and set(value) == {"set"}:
            value = value["set"]
        if isinstance(value, list):
            value = sorted(value)
        expr = {"match": {**expr["match"], "right": value}}
    return json.dumps(expr, sort_keys=True, separators=(",", ":"))

def parse(doc):
    if not isinstance(doc, dict) or not isinstance(doc.get("nftables"), list):
        raise ValueError("Missing nftables JSON array")
    entries = doc["nftables"]
    chains = [entry["chain"] for entry in entries
              if isinstance(entry, dict) and isinstance(entry.get("chain"), dict)
              and all(entry["chain"].get(k) == v for k, v in
                      (("family", FAMILY), ("table", TABLE), ("name", CHAIN)))]
    if len(chains) != 1:
        raise ValueError("Expected exactly one target chain")
    chain = chains[0]
    if any(chain.get(k) != v for k, v in
           (("type", "filter"), ("hook", "forward"), ("policy", "drop"))):
        raise ValueError("Unexpected chain type, hook or default policy")
    rules = [entry["rule"] for entry in entries
             if isinstance(entry, dict) and isinstance(entry.get("rule"), dict)
             and all(entry["rule"].get(k) == v for k, v in
                     (("family", FAMILY), ("table", TABLE), ("chain", CHAIN)))]
    if len(rules) != 4:
        raise ValueError(f"Expected four target rules, found {len(rules)}")
    found = {}
    for rule in rules:
        expressions = rule.get("expr")
        if not isinstance(expressions, list) or len(expressions) < 2:
            raise ValueError("Invalid rule expression list")
        counter_expr, verdict_expr = expressions[-2:]
        if not isinstance(counter_expr, dict) or set(counter_expr) != {"counter"}:
            raise ValueError("Expected penultimate counter expression")
        counts = counter_expr["counter"]
        if not isinstance(counts, dict) or set(counts) != {"packets", "bytes"}:
            raise ValueError("Unexpected counter fields")
        if any(type(counts[k]) is not int or counts[k] < 0 for k in ("packets", "bytes")):
            raise ValueError("Invalid counter values")
        if not isinstance(verdict_expr, dict) or len(verdict_expr) != 1:
            raise ValueError("Invalid terminal verdict")
        verdict, value = next(iter(verdict_expr.items()))
        if verdict not in ("accept", "drop") or value is not None:
            raise ValueError("Unsupported terminal verdict")
        got = sorted(normalized(item) for item in expressions[:-2])
        matches = []
        for name, (patterns, expected_verdict) in EXPECTED.items():
            if verdict == expected_verdict and got == sorted(normalized(p) for p in patterns):
                matches.append(name)
        if len(matches) != 1 or matches[0] in found:
            raise ValueError("Unknown or duplicated rule")
        found[matches[0]] = {"packets": counts["packets"], "bytes": counts["bytes"]}
    if set(found) != set(EXPECTED):
        raise ValueError("Missing expected counter")
    return {"schema_version": "1.0", "table": f"{FAMILY} {TABLE}",
            "chain": CHAIN, "counters": {name: found[name] for name in EXPECTED}}

def fixture():
    chain = {"family": FAMILY, "table": TABLE, "name": CHAIN,
             "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}
    entries = [{"metainfo": {"json_schema_version": 1}}, {"chain": chain}]
    for idx, (name, (patterns, verdict)) in enumerate(EXPECTED.items()):
        expr = [*patterns, {"counter": {"packets": idx + 1, "bytes": 64 * (idx + 1)}},
                {verdict: None}]
        entries.append({"rule": {"family": FAMILY, "table": TABLE,
                                 "chain": CHAIN, "handle": idx + 2, "expr": expr}})
    return {"nftables": entries}

def self_test():
    good = fixture()
    result = parse(good)
    assert len(result["counters"]) == 4
    assert result["counters"]["allow_emp_app"]["packets"] == 2
    import copy
    for kind in ("wrong_policy", "wrong_port", "duplicate", "bad_counter", "missing_rule"):
        bad = copy.deepcopy(good)
        if kind == "wrong_policy":
            bad["nftables"][1]["chain"]["policy"] = "accept"
        elif kind == "wrong_port":
            bad["nftables"][3]["rule"]["expr"][4]["match"]["right"] = 9090
        elif kind == "duplicate":
            bad["nftables"].append(copy.deepcopy(bad["nftables"][3]))
        elif kind == "bad_counter":
            bad["nftables"][2]["rule"]["expr"][-2]["counter"]["packets"] = -1
        else:
            bad["nftables"].pop()
        try:
            parse(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Unsafe sample accepted: {kind}")
    print("V08_COUNTER_PARSER_SELF_TEST=PASS")
    print("EXPECTED_RULE_COUNTERS=4")
    print("REJECTED_INVALID_FIXTURES=5")
    print("NETWORK_TESTS_EXECUTED=0")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--file", type=Path, help="Saved nft -j list chain JSON")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        print(json.dumps(parse(json.loads(args.file.read_text(encoding="utf-8"))), indent=2))

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, AssertionError) as exc:
        print(f"V08_COUNTER_PARSER_ERROR={exc}", file=sys.stderr)
        sys.exit(1)
