#!/usr/bin/env python3
"""Read-only validation of a completed V0.4 six-scenario regression log.

This script does not run networking commands or assume that past evidence is a
new test run. It is the offline parsing foundation for V0.5 reporting.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

EXPECTED_SCENARIOS = (
    "employee_to_app_tcp8080",
    "app_to_data_tcp5432",
    "employee_to_data_icmp",
    "employee_to_data_tcp5432",
    "employee_to_app_tcp8081",
    "data_to_app_tcp8080",
)


def validate_log(content: str) -> tuple[dict[str, object], list[str]]:
    """Require unique scenario results and a consistent final summary."""
    issues: list[str] = []
    scenarios: dict[str, str] = {}
    preflight: list[str] = []
    counts: dict[str, list[str]] = {"passed": [], "failed": []}
    final_results: list[str] = []
    exit_codes: list[str] = []

    for line_number, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if line.startswith(("PASS|", "FAIL|")):
            parts = line.split("|", 2)
            if len(parts) != 3 or not parts[2].strip():
                issues.append(f"line {line_number}: malformed test record")
                continue
            verdict, name, _detail = parts
            if name == "preflight":
                preflight.append(verdict)
                continue
            if name not in EXPECTED_SCENARIOS:
                issues.append(f"line {line_number}: unexpected test name {name!r}")
            elif name in scenarios:
                issues.append(f"line {line_number}: duplicate test {name!r}")
            else:
                scenarios[name] = verdict
        elif line.startswith("SUMMARY|"):
            parts = line.split("|")
            if len(parts) != 3 or parts[1] not in counts:
                issues.append(f"line {line_number}: malformed summary")
            else:
                counts[parts[1]].append(parts[2])
        elif line.startswith("REGRESSION_RESULT="):
            final_results.append(line.partition("=")[2])
        elif line.startswith("REGRESSION_EXIT_CODE="):
            exit_codes.append(line.partition("=")[2])
        elif line.startswith("ERROR|"):
            issues.append(f"line {line_number}: test runner reported an error")

    if preflight != ["PASS"]:
        issues.append("expected exactly one PASS|preflight record")
    missing = [name for name in EXPECTED_SCENARIOS if name not in scenarios]
    if missing:
        issues.append("missing scenarios: " + ", ".join(missing))
    failures = [name for name, verdict in scenarios.items() if verdict != "PASS"]
    if failures:
        issues.append("failed scenarios: " + ", ".join(failures))

    expected_counts = {"passed": str(len(EXPECTED_SCENARIOS)), "failed": "0"}
    for kind, expected in expected_counts.items():
        if counts[kind] != [expected]:
            issues.append(f"expected exactly SUMMARY|{kind}|{expected}")
    if final_results != ["PASS"]:
        issues.append("expected exactly REGRESSION_RESULT=PASS")
    if exit_codes != ["0"]:
        issues.append("expected exactly REGRESSION_EXIT_CODE=0")

    result: dict[str, object] = {
        "expected_scenarios": list(EXPECTED_SCENARIOS),
        "scenario_results": scenarios,
        "verified_pass_count": sum(v == "PASS" for v in scenarios.values()),
        "preflight_pass": preflight == ["PASS"],
        "valid": not issues,
    }
    return result, issues


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a previously recorded V0.4 regression log (read-only)."
    )
    parser.add_argument("log_file", type=Path, help="Path to an existing V0.4 log")
    args = parser.parse_args()

    try:
        if args.log_file.stat().st_size > 2_000_000:
            print("ERROR: log exceeds the 2 MB offline-parser limit", file=sys.stderr)
            return 2
        content = args.log_file.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        print(f"ERROR: cannot read log: {exc}", file=sys.stderr)
        return 2

    result, issues = validate_log(content)
    print("=== V0.5 OFFLINE REGRESSION LOG CHECK ===")
    print(f"SOURCE={args.log_file}")
    print(f"SCENARIOS_FOUND={len(result['scenario_results'])}/6")
    print(f"SCENARIOS_PASSED={result['verified_pass_count']}/6")
    print(f"PREFLIGHT={'PASS' if result['preflight_pass'] else 'FAIL'}")
    for issue in issues:
        print(f"VALIDATION_ERROR={issue}")
    print(f"LOG_VALIDATION={'PASS' if result['valid'] else 'FAIL'}")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
