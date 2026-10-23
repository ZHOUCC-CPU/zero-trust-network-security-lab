#!/usr/bin/env python3
"""Export an already validated V0.4 regression log to JSON and CSV.

Offline only: no network commands, privilege escalation, or changes to source logs.
Requires v05_parse_regression.py alongside this script.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys

from v05_parse_regression import EXPECTED_SCENARIOS, validate_log

MAX_LOG_BYTES = 2_000_000
EXPECTED_BEHAVIOR = {
    "employee_to_app_tcp8080": "ALLOW",
    "app_to_data_tcp5432": "ALLOW",
    "employee_to_data_icmp": "DENY",
    "employee_to_data_tcp5432": "DENY",
    "employee_to_app_tcp8081": "DENY",
    "data_to_app_tcp8080": "DENY",
}


def read_log(path: Path) -> tuple[bytes, str]:
    with path.open("rb") as f:
        raw = f.read(MAX_LOG_BYTES + 1)
    if len(raw) > MAX_LOG_BYTES:
        raise ValueError("source log exceeds the 2 MB limit")
    return raw, raw.decode("utf-8-sig")


def build_rows(text: str) -> list[dict[str, object]]:
    # validate_log() already guaranteed exactly one valid record per scenario.
    details: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split("|", 2)
        if len(parts) == 3 and parts[0] == "PASS" and parts[1] in EXPECTED_SCENARIOS:
            details[parts[1]] = parts[2].strip()

    rows = []
    for name in EXPECTED_SCENARIOS:
        detail = details[name]
        match = re.search(r"\bcounter \+(\d+)\b", detail)
        rows.append({
            "scenario": name,
            "expected_behavior": EXPECTED_BEHAVIOR[name],
            "verdict": "PASS",
            "detail": detail,
            "observed_rule_counter_increase_packets": int(match.group(1)) if match else None,
        })
    return rows


def csv_content(rows: list[dict[str, object]], source: str, digest: str) -> str:
    out = io.StringIO(newline="")
    fieldnames = [
        "source_log", "source_sha256", "scenario", "expected_behavior",
        "verdict", "detail", "observed_rule_counter_increase_packets",
    ]
    writer = csv.DictWriter(out, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for item in rows:
        writer.writerow({
            "source_log": source,
            "source_sha256": digest,
            **{k: "" if v is None else v for k, v in item.items()},
        })
    return out.getvalue()


def write_new_file(path: Path, content: str) -> None:
    # Exclusive create: never silently overwrite an existing report or symlink.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export a previously recorded, fully passing V0.4 log to JSON/CSV."
    )
    parser.add_argument("log_file", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/v05"))
    args = parser.parse_args()

    try:
        raw, text = read_log(args.log_file)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR|source|{exc}", file=sys.stderr)
        return 2

    result, issues = validate_log(text)
    if issues or not result["valid"]:
        for issue in issues:
            print(f"VALIDATION_ERROR={issue}", file=sys.stderr)
        print("EXPORT_RESULT=FAIL_INVALID_LOG", file=sys.stderr)
        return 1

    rows = build_rows(text)
    digest = hashlib.sha256(raw).hexdigest()
    source = str(args.log_file)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report = {
        "schema_version": "1.0",
        "report_type": "offline_conversion_of_existing_experiment_log",
        "new_network_test_executed": False,
        "generated_at_utc": generated,
        "source_log": source,
        "source_sha256": digest,
        "validation": {
            "passed": True,
            "preflight_passed": bool(result["preflight_pass"]),
            "expected_scenarios": len(EXPECTED_SCENARIOS),
            "passed_scenarios": len(rows),
            "failed_scenarios": 0,
            "recorded_runner_exit_code": 0,
        },
        "scenarios": rows,
    }
    json_text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    csv_text = csv_content(rows, source, digest)

    stem = args.log_file.stem
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,180}", stem):
        print("ERROR|source|unsafe or unsupported log filename", file=sys.stderr)
        return 2
    json_path = args.output_dir / f"V0.5_{stem}.json"
    csv_path = args.output_dir / f"V0.5_{stem}.csv"
    if any(p.exists() or p.is_symlink() for p in (json_path, csv_path)):
        print("ERROR|output|report already exists; refusing overwrite", file=sys.stderr)
        return 2

    try:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        write_new_file(json_path, json_text)
        try:
            write_new_file(csv_path, csv_text)
        except BaseException:
            json_path.unlink(missing_ok=True)
            raise
    except OSError as exc:
        print(f"ERROR|output|{exc}", file=sys.stderr)
        return 2

    print("=== V0.5 STRUCTURED REPORT EXPORT ===")
    print("SOURCE_LOG_VALIDATION=PASS")
    print(f"SCENARIOS_EXPORTED={len(rows)}/{len(EXPECTED_SCENARIOS)}")
    print(f"JSON_FILE={json_path}")
    print(f"CSV_FILE={csv_path}")
    print("EXPORT_RESULT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
