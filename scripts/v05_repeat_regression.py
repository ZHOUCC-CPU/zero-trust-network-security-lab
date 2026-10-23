#!/usr/bin/env python3
"""Bounded V0.5 live-regression orchestrator (no topology/policy changes).

Default action is a read-only preview. --execute re-runs the reviewed root-owned
V0.4 test script, validates each completed six-scenario result, and saves
per-round evidence plus machine-readable summaries. An ACTIVE V0.4 lab is
required for --execute and must be prepared separately.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from v05_parse_regression import EXPECTED_SCENARIOS, validate_log
from v05_export_regression import build_rows

RUNNER = Path("/root/ztlab-v03-reviewed/test_v04_firewall.sh")
MAX_ROUNDS = 10
MAX_LOG_BYTES = 2_000_000


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def write_exclusive(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_once(index: int, folder: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # The entire runner, including its temporary HTTP services, runs under a
    # root-controlled timeout, and the runner handles TERM and EXIT cleanup.
    command = [
        "sudo", "-n", "timeout", "--signal=TERM", "--kill-after=10s", "120s",
        "bash", str(RUNNER),
    ]
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, errors="replace", check=False)
        output = proc.stdout
        code = proc.returncode
    except OSError as exc:
        output = f"ERROR|runner|could not launch: {exc}\n"
        code = 127

    finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # Only one wrapper line is appended. validate_log() requires exactly one
    # recorded exit-code field, and never treats an interrupted run as success.
    full_log = (
        f"=== V0.5 LIVE REGRESSION ROUND {index:02d} ===\n"
        f"STARTED_UTC={started}\n"
        f"{output.rstrip()}\n"
        f"REGRESSION_EXIT_CODE={code}\n"
        f"FINISHED_UTC={finished}\n"
    )
    path = folder / f"round_{index:02d}.txt"
    write_exclusive(path, full_log)
    issues: list[str] = []
    if len(full_log.encode("utf-8")) > MAX_LOG_BYTES:
        issues.append("round log exceeds the 2 MB validation limit")
    if code != 0:
        issues.append(f"runner returned nonzero exit code {code}")
    parsed, parse_issues = validate_log(full_log)
    issues.extend(parse_issues)
    valid = not issues and bool(parsed["valid"])
    rows = build_rows(full_log) if valid else []
    record: dict[str, object] = {
        "round": index,
        "started_at_utc": started,
        "finished_at_utc": finished,
        "log_file": str(path),
        "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "runner_exit_code": code,
        "scenario_pass_count": int(parsed["verified_pass_count"]),
        "valid": valid,
        "issues": issues,
    }
    return record, rows


def export_csv(path: Path, records: list[tuple[int, list[dict[str, object]]]]) -> None:
    columns = ["round", "scenario", "expected_behavior", "verdict", "detail",
               "observed_rule_counter_increase_packets"]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for index, rows in records:
            for item in rows:
                writer.writerow({"round": index, **item})


def execute(rounds: int, output_base: Path) -> int:
    if os.geteuid() == 0:
        print("ERROR: run this orchestrator as your normal user, not sudo.", file=sys.stderr)
        return 2
    if not shutil.which("sudo") or not shutil.which("timeout"):
        print("ERROR: sudo and timeout are required.", file=sys.stderr)
        return 2
    # Fail before creating evidence if cached authentication is unavailable.
    # Never prompt inside captured child-process output.
    auth = subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False)
    if auth.returncode != 0:
        print("ERROR: run 'sudo -v' interactively first; then retry --execute.",
              file=sys.stderr)
        return 2
    try:
        output_base.mkdir(parents=True, exist_ok=True)
        session_dir = output_base / f"run_{utc_stamp()}_{os.getpid()}"
        session_dir.mkdir(mode=0o700)
    except OSError as exc:
        print(f"ERROR: cannot create output directory: {exc}", file=sys.stderr)
        return 2
    print(f"SESSION_DIR={session_dir}", flush=True)
    details: list[dict[str, object]] = []
    completed: list[tuple[int, list[dict[str, object]]]] = []
    try:
        for index in range(1, rounds + 1):
            print(f"ROUND_START={index}/{rounds}", flush=True)
            record, rows = run_once(index, session_dir)
            details.append(record)
            print(f"ROUND_{index:02d}={'PASS' if record['valid'] else 'FAIL'}"
                  f" (scenarios={record['scenario_pass_count']}/{len(EXPECTED_SCENARIOS)},"
                  f" exit={record['runner_exit_code']})", flush=True)
            if not record["valid"]:
                for issue in record["issues"]:
                    print(f"ROUND_ERROR={issue}", flush=True)
                break
            completed.append((index, rows))
    except KeyboardInterrupt:
        print("INTERRUPTED: stopping future rounds and preserving existing evidence.",
              file=sys.stderr)
    finally:
        succeeded = len(details) == rounds and all(r["valid"] for r in details)
        summary = {
            "schema_version": "1.0",
            "report_type": "live_repeated_v04_regression",
            "new_network_tests_executed": bool(details),
            "run_started_as_normal_user": True,
            "rounds_requested": rounds,
            "rounds_attempted": len(details),
            "rounds_passed": len(completed),
            "all_passed": succeeded,
            "rounds": details,
            "note": "This tool runs tests only; topology and nftables setup/teardown are separate.",
        }
        try:
            write_exclusive(session_dir / "summary.json",
                            json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
            export_csv(session_dir / "scenarios.csv", completed)
        except OSError as exc:
            print(f"ERROR: could not save summary: {exc}", file=sys.stderr)
            return 2
        print(f"ROUNDS_PASSED={len(completed)}/{rounds}")
        print(f"REPEAT_RESULT={'PASS' if succeeded else 'FAIL'}")
    return 0 if succeeded else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=3,
                        help=f"number of live regression rounds (1 to {MAX_ROUNDS}, default 3)")
    parser.add_argument("--output-dir", type=Path, default=Path("evidence/v05_runs"))
    parser.add_argument("--execute", action="store_true",
                        help="explicit opt-in to live namespace traffic tests; requires active V0.4")
    args = parser.parse_args()
    if not 1 <= args.rounds <= MAX_ROUNDS:
        parser.error(f"--rounds must be between 1 and {MAX_ROUNDS}")
    if not args.execute:
        print("=== V0.5 REPEATED TEST PREVIEW (READ ONLY) ===")
        print(f"ROUNDS_PLANNED={args.rounds}")
        print(f"SECURE_ROOT_RUNNER={RUNNER}")
        print(f"EVIDENCE_DIRECTORY={args.output_dir}")
        print("REQUIRES_ACTIVE_V04_TOPOLOGY=YES")
        print("REQUIRES_SUDO_AUTH_FOR_LIVE_RUN=YES")
        print("PREVIEW_NETWORK_TESTS_EXECUTED=0")
        return 0
    return execute(args.rounds, args.output_dir)


if __name__ == "__main__":
    raise SystemExit(main())
