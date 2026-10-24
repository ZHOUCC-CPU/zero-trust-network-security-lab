#!/usr/bin/env python3
"""V0.8 offline auditor: cross-check counter snapshots, behavioral records,
CSV projections and a SHA-256 inventory. Does not run nft/ip/sudo or probes.

Session layout (all files in one directory):
    audit_records.json   {schema_version, data_origin, records: [case, ...]}
    audit_records.csv    UTF-8 CSV; fields in CSV_FIELDS below
    manifest.json        {schema_version, data_origin, sha256: {filename: hex, ...}}
    <case>.before.json   raw output of nft -j list chain inet ztlab_v04 forward
    <case>.after.json    raw output of the same command
    <case>.behavior.json {scenario_id, round, observed_behavior, result, exit_code}

A positive rule-counter delta alone is NOT proof of allow/deny: the behavioral
file supplies additional bounded-test observations. Hashes establish internal
consistency, not origin authenticity. Synthetic self-test data are NOT results.
"""

import argparse
import csv
import hashlib
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from v08_counter_delta import add_to_counter, compare
from v08_counter_parser import EXPECTED, fixture

SCHEMA = "1.0"
CSV_FIELDS = (
    "round", "scenario_id", "expected_verdict", "observed_behavior", "test_status",
    "expected_counter", "packets_before", "packets_after", "packet_delta",
    "bytes_before", "bytes_after", "byte_delta", "timestamp_utc",
    "before_file", "after_file", "behavior_file",
)
INTEGER_FIELDS = (
    "round", "packets_before", "packets_after", "packet_delta",
    "bytes_before", "bytes_after", "byte_delta",
)
CASE_FILES = ("before_file", "after_file", "behavior_file")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
KNOWN_CASES = {
    "employee_to_app_tcp8080": ("ALLOW", "allow_emp_app"),
    "app_to_data_tcp5432": ("ALLOW", "allow_app_data"),
    "employee_to_data_icmp": ("DENY", "drop"),
    "employee_to_data_tcp5432": ("DENY", "drop"),
    "employee_to_app_tcp8081": ("DENY", "drop"),
    "data_to_app_tcp8080": ("DENY", "drop"),
}


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def json_read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def json_write(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_relative(session, name):
    require(isinstance(name, str) and name and "\\" not in name,
            "Invalid evidence filename")
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and len(relative.parts) == 1
            and relative.name not in (".", ".."), "Unsafe evidence file path")
    result = session / name
    require(result.is_file() and not result.is_symlink(), f"Missing/unsafe file: {name}")
    return result


def validate_plan(plan):
    require(isinstance(plan, dict) and plan.get("schema_version") == SCHEMA,
            "Invalid plan schema")
    require(type(plan.get("rounds")) is int and plan["rounds"] == 3,
            "Expected exactly three rounds")
    scenarios = plan.get("scenarios")
    require(isinstance(scenarios, list) and len(scenarios) == 6,
            "Expected six scenarios")
    mapping = {}
    for s in scenarios:
        require(isinstance(s, dict), "Invalid scenario")
        name = s.get("id")
        verdict = s.get("expected_verdict")
        counter = s.get("expected_counter")
        require(isinstance(name, str) and name not in mapping,
                "Duplicate/invalid scenario ID")
        require(verdict in ("ALLOW", "DENY") and counter in EXPECTED,
                "Unknown verdict or counter")
        require(KNOWN_CASES.get(name) == (verdict, counter),
                "Unexpected scenario-to-rule mapping")
        mapping[name] = (verdict, counter)
    require(mapping == KNOWN_CASES, "Expected exact six authorized/denied cases")
    return mapping


def validate_session(session, plan, allow_simulated=False):
    require(session.is_dir() and not session.is_symlink(), "Unsafe session directory")
    expected = validate_plan(plan)
    manifest = json_read(safe_relative(session, "manifest.json"))
    records_data = json_read(safe_relative(session, "audit_records.json"))
    require(isinstance(manifest, dict) and manifest.get("schema_version") == SCHEMA,
            "Invalid manifest schema")
    require(isinstance(records_data, dict) and records_data.get("schema_version") == SCHEMA,
            "Invalid records schema")
    origin = records_data.get("data_origin")
    require(origin == "LIVE_ISOLATED_NETWORK" or
            (allow_simulated and origin == "SIMULATED"), "Unacceptable data origin")
    require(manifest.get("data_origin") == origin, "Origin mismatch")
    digest_map = manifest.get("sha256")
    require(isinstance(digest_map, dict) and digest_map, "Missing hash inventory")
    require("manifest.json" not in digest_map, "Manifest must not self-hash")
    actual_names = {p.name for p in session.iterdir() if p.is_file()}
    require(actual_names == set(digest_map) | {"manifest.json"},
            "File inventory differs from manifest")
    for name, digest in digest_map.items():
        require(isinstance(digest, str) and HEX64.fullmatch(digest),
                "Invalid SHA-256 digest")
        require(sha256_file(safe_relative(session, name)) == digest,
                f"SHA-256 mismatch: {name}")

    records = records_data.get("records")
    require(isinstance(records, list) and len(records) == 18,
            "Expected 18 case records")
    observed_keys = set()
    referenced = {"audit_records.json", "audit_records.csv"}
    for record in records:
        require(isinstance(record, dict) and set(record) == set(CSV_FIELDS),
                "Unexpected case schema")
        for field in INTEGER_FIELDS:
            require(type(record[field]) is int and record[field] >= 0,
                    f"Invalid nonnegative integer: {field}")
        round_number = record["round"]
        case_id = record["scenario_id"]
        require(round_number in (1, 2, 3) and case_id in expected,
                "Unknown round or scenario")
        key = (round_number, case_id)
        require(key not in observed_keys, "Repeated case")
        observed_keys.add(key)
        verdict, counter = expected[case_id]
        require(record["expected_verdict"] == verdict and
                record["expected_counter"] == counter,
                "Expected verdict/rule differs from plan")
        require(record["observed_behavior"] == verdict and
                record["test_status"] == "PASS",
                "Unsuccessful or inconsistent behavioral result")
        ts = record["timestamp_utc"]
        require(isinstance(ts, str) and ts.endswith("Z"), "Missing UTC timestamp")
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        require(parsed.tzinfo == timezone.utc, "Timestamp not UTC")

        for field in CASE_FILES:
            name = record[field]
            require(name not in referenced, "Duplicate evidence filename")
            referenced.add(name)
            require(name in digest_map, "Unhashed evidence file")
        before = json_read(safe_relative(session, record["before_file"]))
        after = json_read(safe_relative(session, record["after_file"]))
        delta = compare(before, after, counter)
        actual = delta["deltas"][counter]
        require(delta["expected_counter_packets_increased"] is True,
                "Expected rule did not count any packets")
        for field in ("packets_before", "packets_after", "packet_delta",
                      "bytes_before", "bytes_after", "byte_delta"):
            # compare() emits identical keys for these quantities.
            require(record[field] == actual[field], f"Counter result mismatch: {field}")
        behavior = json_read(safe_relative(session, record["behavior_file"]))
        require(isinstance(behavior, dict) and behavior.get("scenario_id") == case_id
                and behavior.get("round") == round_number
                and behavior.get("observed_behavior") == verdict
                and behavior.get("result") == "PASS"
                and type(behavior.get("exit_code")) is int
                and behavior["exit_code"] == 0,
                "Behavior evidence does not support record")
    require(observed_keys == {(n, scenario) for n in (1, 2, 3) for scenario in expected},
            "Missing planned scenario")
    require(referenced == set(digest_map), "Unreferenced/extra evidence in inventory")
    with safe_relative(session, "audit_records.csv").open(
            encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        require(reader.fieldnames == list(CSV_FIELDS), "CSV header mismatch")
        csv_rows = list(reader)
    require(len(csv_rows) == len(records), "CSV row count mismatch")
    for index, (record, row) in enumerate(zip(records, csv_rows), start=1):
        require(row == {field: str(record[field]) for field in CSV_FIELDS},
                f"CSV and JSON differ at row {index}")
    return len(records)


def make_fixture_session(session, plan):
    counters = fixture()
    records = []
    for round_number in (1, 2, 3):
        for scenario in plan["scenarios"]:
            case_id = scenario["id"]
            counter = scenario["expected_counter"]
            prefix = f"r{round_number}_{case_id}"
            before_file = f"{prefix}.before.json"
            after_file = f"{prefix}.after.json"
            behavior_file = f"{prefix}.behavior.json"
            before = json.loads(json.dumps(counters))
            after = add_to_counter(before, counter, 2, 128)
            json_write(session / before_file, before)
            json_write(session / after_file, after)
            json_write(session / behavior_file, {
                "scenario_id": case_id, "round": round_number,
                "observed_behavior": scenario["expected_verdict"],
                "result": "PASS", "exit_code": 0,
            })
            change = compare(before, after, counter)["deltas"][counter]
            records.append({
                "round": round_number,
                "scenario_id": case_id,
                "expected_verdict": scenario["expected_verdict"],
                "observed_behavior": scenario["expected_verdict"],
                "test_status": "PASS", "expected_counter": counter,
                **change,
                "timestamp_utc": "2026-10-24T00:00:00Z",
                "before_file": before_file, "after_file": after_file,
                "behavior_file": behavior_file,
            })
            counters = after
    json_write(session / "audit_records.json", {
        "schema_version": SCHEMA, "data_origin": "SIMULATED", "records": records,
    })
    with (session / "audit_records.csv").open(
            "w", encoding="utf-8", newline="") as dest:
        writer = csv.DictWriter(dest, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)
    rebuild_manifest(session, "SIMULATED")


def rebuild_manifest(session, origin):
    json_write(session / "manifest.json", {
        "schema_version": SCHEMA, "data_origin": origin,
        "sha256": {path.name: sha256_file(path) for path in sorted(session.iterdir())
                   if path.name != "manifest.json"},
    })


def self_test():
    plan = {"schema_version": SCHEMA, "rounds": 3, "scenarios": [
        {"id": name, "expected_verdict": verdict, "expected_counter": counter}
        for name, (verdict, counter) in KNOWN_CASES.items()]}
    with tempfile.TemporaryDirectory(prefix="v08-audit-offline-") as temp:
        session = Path(temp)
        make_fixture_session(session, plan)
        require(validate_session(session, plan, allow_simulated=True) == 18,
                "Valid simulated fixture rejected")
        invalid_cases = 0
        def must_reject():
            nonlocal invalid_cases
            try:
                validate_session(session, plan, allow_simulated=True)
            except (EvidenceError, ValueError, KeyError, json.JSONDecodeError):
                invalid_cases += 1
            else:
                raise AssertionError("Corrupted evidence accepted")

        csv_path = session / "audit_records.csv"
        original = csv_path.read_bytes()
        csv_path.write_bytes(original + b"extra\n")
        must_reject()  # manifest checksum catches tampering
        csv_path.write_bytes(original)

        records_path = session / "audit_records.json"
        original = records_path.read_bytes()
        data = json.loads(original)
        data["records"][0]["packet_delta"] = 9000
        json_write(records_path, data)
        rebuild_manifest(session, "SIMULATED")
        must_reject()  # counter/JSON conflict despite updated hashes
        records_path.write_bytes(original)
        rebuild_manifest(session, "SIMULATED")

        data = json.loads(original)
        data["records"].pop()
        json_write(records_path, data)
        rebuild_manifest(session, "SIMULATED")
        must_reject()  # missing scenario despite updated hashes
        records_path.write_bytes(original)
        rebuild_manifest(session, "SIMULATED")

        behavior_path = next(session.glob("*.behavior.json"))
        original = behavior_path.read_bytes()
        data = json.loads(original)
        data["observed_behavior"] = "ERROR"
        json_write(behavior_path, data)
        rebuild_manifest(session, "SIMULATED")
        must_reject()  # behavior/record contradiction
        behavior_path.write_bytes(original)
        rebuild_manifest(session, "SIMULATED")

        must_reject_live = False
        try:
            validate_session(session, plan, allow_simulated=False)
        except EvidenceError:
            must_reject_live = True
        require(must_reject_live, "Simulated data accepted as live")
        invalid_cases += 1
    print("V08_EVIDENCE_VALIDATOR_SELF_TEST=PASS")
    print("SIMULATED_CASES_VALIDATED=18")
    print(f"REJECTED_INVALID_FIXTURES={invalid_cases}")
    print("NETWORK_TESTS_EXECUTED=0")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--check-plan", type=Path)
    group.add_argument("--session", type=Path)
    parser.add_argument("--plan", type=Path)
    args = parser.parse_args()
    if args.self_test:
        require(args.plan is None, "Self-test must not use an external plan")
        self_test()
    elif args.check_plan:
        require(args.plan is None, "--check-plan already selects the plan")
        cases = validate_plan(json_read(args.check_plan))
        print("V08_EVIDENCE_PLAN_CHECK=PASS")
        print(f"SCENARIOS={len(cases)}")
        print("EXPECTED_RECORDS=18")
        print("NETWORK_TESTS_EXECUTED=0")
    else:
        require(args.plan is not None, "--session requires --plan")
        count = validate_session(args.session, json_read(args.plan))
        print("V08_EVIDENCE_VALIDATION=PASS")
        print(f"VERIFIED_LIVE_CASES={count}/18")


if __name__ == "__main__":
    try:
        main()
    except (OSError, EvidenceError, ValueError, TypeError, KeyError,
            json.JSONDecodeError) as exc:
        print(f"V08_EVIDENCE_VALIDATOR_ERROR={exc}", file=sys.stderr)
        sys.exit(1)
