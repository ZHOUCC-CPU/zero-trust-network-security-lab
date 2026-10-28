#!/usr/bin/env python3
"""V0.7 bounded TCP connection latency probe."""
import argparse
import json
import math
import os
from pathlib import Path
import socket
import statistics
import time

FLOWS = {
    "employee_to_app_tcp8080":
        ("employee-ns", "10.200.20.2", 8080),
    "app_to_data_tcp5432":
        ("app-ns", "10.200.30.2", 5432),
}

COUNT = 30
TIMEOUT = 2.0
INTERVAL = 0.05


def check_plan():
    path = Path("tests/v07_benchmark_plan.json")
    plan = json.loads(path.read_text(encoding="utf-8"))

    if not (plan['conditions'] == ['baseline', 'segmented']):
        raise ValueError("Invalid benchmark plan: plan['conditions'] == ['baseline', 'segmented']")
    if not (plan['rounds_per_condition'] == 3):
        raise ValueError("Invalid benchmark plan: plan['rounds_per_condition'] == 3")
    if not (plan['latency']['method'] == 'TCP_CONNECT'):
        raise ValueError("Invalid benchmark plan: plan['latency']['method'] == 'TCP_CONNECT'")
    if not (plan['latency']['probes_per_flow'] == COUNT):
        raise ValueError("Invalid benchmark plan: plan['latency']['probes_per_flow'] == COUNT")
    if not (plan['latency']['timeout_seconds'] == TIMEOUT):
        raise ValueError("Invalid benchmark plan: plan['latency']['timeout_seconds'] == TIMEOUT")

    observed = {
        f["id"]: (
            f["source_namespace"],
            f["destination_ip"],
            f["port"]
        )
        for f in plan["flows"]
    }

    if not (observed == FLOWS):
        raise ValueError('Invalid benchmark plan: observed == FLOWS')
    if not (plan['safety']['no_external_traffic'] is True):
        raise ValueError("Invalid benchmark plan: plan['safety']['no_external_traffic'] is True")

    print("TCP_LATENCY_PLAN_CHECK=PASS")
    print("ALLOWED_FLOWS=2")
    print("PROBES_PER_FLOW=30")
    print("NETWORK_PROBES_EXECUTED=0")


def run_probe(flow_id):
    if os.geteuid() != 0:
        raise RuntimeError("Live execution requires reviewed root staging")

    script_path = Path(__file__)
    if script_path.is_symlink():
        raise RuntimeError("Symlinked executable refused")

    script_stat = script_path.stat()
    if script_stat.st_uid != 0 or script_stat.st_mode & 0o022:
        raise RuntimeError("Script ownership/permissions unsafe")

    namespace, address, port = FLOWS[flow_id]

    expected = os.stat(f"/run/netns/{namespace}")
    actual = os.stat("/proc/self/ns/net")

    if (expected.st_dev, expected.st_ino) != (
        actual.st_dev, actual.st_ino
    ):
        raise RuntimeError("Source network namespace mismatch")

    measurements = []
    errors = []

    for index in range(COUNT):
        start = time.perf_counter_ns()

        try:
            with socket.create_connection(
                (address, port), timeout=TIMEOUT
            ):
                pass

            elapsed_ms = (
                time.perf_counter_ns() - start
            ) / 1_000_000

            measurements.append(round(elapsed_ms, 6))

        except OSError as exc:
            errors.append({
                "probe": index + 1,
                "error_type": type(exc).__name__
            })

        if index + 1 < COUNT:
            time.sleep(INTERVAL)

    ordered = sorted(measurements)

    result = {
        "schema_version": "1.0",
        "flow_id": flow_id,
        "source_namespace": namespace,
        "destination_ip": address,
        "destination_port": port,
        "requested_probes": COUNT,
        "successful_probes": len(measurements),
        "failed_probes": len(errors),
        "latency_ms": measurements,
        "errors": errors,
        "mean_ms": (
            round(statistics.mean(ordered), 6)
            if ordered else None
        ),
        "median_ms": (
            round(statistics.median(ordered), 6)
            if ordered else None
        ),
        "p95_ms": (
            ordered[math.ceil(0.95 * len(ordered)) - 1]
            if ordered else None
        ),
    }

    print(json.dumps(result, indent=2))
    return 0 if len(measurements) == COUNT else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--flow", choices=FLOWS)
    args = parser.parse_args()

    if not args.execute:
        check_plan()
        return 0

    if not args.flow:
        parser.error("--flow is required with --execute")

    return run_probe(args.flow)


if __name__ == "__main__":
    raise SystemExit(main())
