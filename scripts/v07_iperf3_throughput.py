#!/usr/bin/env python3
"""V0.7 bounded TCP throughput measurement."""
import argparse
import json
import math
import os
from pathlib import Path
import subprocess
import sys

FLOWS = {
    "employee_to_app_tcp8080": (
        "employee-ns", "10.200.20.2", 8080
    ),
    "app_to_data_tcp5432": (
        "app-ns", "10.200.30.2", 5432
    ),
}

DURATION = 5
TARGET_MBPS = 50
TIMEOUT = 20


def check_plan():
    plan = json.loads(
        Path("tests/v07_benchmark_plan.json").read_text(
            encoding="utf-8"
        )
    )

    throughput = plan["throughput"]

    if not (plan['conditions'] == ['baseline', 'segmented']):
        raise ValueError("Invalid benchmark plan: plan['conditions'] == ['baseline', 'segmented']")
    if not (plan['rounds_per_condition'] == 3):
        raise ValueError("Invalid benchmark plan: plan['rounds_per_condition'] == 3")
    if not (throughput['tool'] == 'iperf3'):
        raise ValueError("Invalid benchmark plan: throughput['tool'] == 'iperf3'")
    if not (throughput['protocol'] == 'TCP'):
        raise ValueError("Invalid benchmark plan: throughput['protocol'] == 'TCP'")
    if not (throughput['duration_seconds'] == DURATION):
        raise ValueError("Invalid benchmark plan: throughput['duration_seconds'] == DURATION")
    if not (throughput['parallel_streams'] == 1):
        raise ValueError("Invalid benchmark plan: throughput['parallel_streams'] == 1")
    if not (throughput['target_bitrate_mbps'] == TARGET_MBPS):
        raise ValueError("Invalid benchmark plan: throughput['target_bitrate_mbps'] == TARGET_MBPS")

    configured = {
        f["id"]: (
            f["source_namespace"],
            f["destination_ip"],
            f["port"],
        )
        for f in plan["flows"]
    }

    if not (configured == FLOWS):
        raise ValueError('Invalid benchmark plan: configured == FLOWS')
    if not (plan['safety']['no_external_traffic'] is True):
        raise ValueError("Invalid benchmark plan: plan['safety']['no_external_traffic'] is True")

    print("THROUGHPUT_PLAN_CHECK=PASS")
    print("AUTHORIZED_FLOWS=2")
    print("TARGET_BITRATE_MBPS=50")
    print("DURATION_SECONDS=5")
    print("NETWORK_TESTS_EXECUTED=0")


def measure(flow_id):
    if os.geteuid() != 0:
        raise RuntimeError("Reviewed root staging is required")

    source, address, port = FLOWS[flow_id]

    file_stat = os.stat(__file__)
    if file_stat.st_uid != 0 or file_stat.st_mode & 0o022:
        raise RuntimeError("Script ownership/permissions unsafe")

    source_ns = os.stat(f"/run/netns/{source}")
    current_ns = os.stat("/proc/self/ns/net")

    if (source_ns.st_dev, source_ns.st_ino) != (
        current_ns.st_dev, current_ns.st_ino
    ):
        raise RuntimeError("Source namespace mismatch")

    command = [
        "iperf3",
        "--client", address,
        "--port", str(port),
        "--time", str(DURATION),
        "--bitrate", f"{TARGET_MBPS}M",
        "--parallel", "1",
        "--connect-timeout", "2000",
        "--json",
    ]

    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"iperf3 failed: exit={proc.returncode}; "
            f"stderr={proc.stderr[:400]}"
        )

    data = json.loads(proc.stdout)

    if data.get("error"):
        raise RuntimeError(f"iperf3 error: {data['error']}")

    end = data["end"]
    received = end["sum_received"]["bits_per_second"]
    sent = end["sum_sent"]["bits_per_second"]

    if not all(
        isinstance(value, (int, float))
        and math.isfinite(value)
        and value > 0
        for value in (received, sent)
    ):
        raise RuntimeError("Invalid throughput measurement")

    result = {
        "schema_version": "1.0",
        "flow_id": flow_id,
        "source_namespace": source,
        "destination_ip": address,
        "destination_port": port,
        "duration_seconds": DURATION,
        "target_bitrate_mbps": TARGET_MBPS,
        "measured_send_mbps": round(sent / 1_000_000, 6),
        "measured_receive_mbps": round(received / 1_000_000, 6),
        "retransmits": end["sum_sent"].get("retransmits"),
        "result": "PASS",
    }

    print(json.dumps(result, indent=2))
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--flow", choices=FLOWS)

    args = parser.parse_args()

    if not args.execute:
        check_plan()
        return 0

    if not args.flow:
        parser.error("--flow required with --execute")

    return measure(args.flow)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError,
            subprocess.TimeoutExpired) as exc:
        print(
            f"THROUGHPUT_PROBE_ERROR={exc}",
            file=sys.stderr
        )
        raise SystemExit(2)
