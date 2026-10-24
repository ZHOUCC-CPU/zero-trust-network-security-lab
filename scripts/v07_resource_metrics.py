#!/usr/bin/env python3
"""V0.7 read-only WSL CPU and memory sampler."""

import argparse
import json
import statistics
import time
from pathlib import Path


def read_cpu():
    line = Path("/proc/stat").read_text().splitlines()[0]
    fields = line.split()

    if fields[0] != "cpu":
        raise RuntimeError("Unexpected /proc/stat format")

    values = [int(v) for v in fields[1:]]
    total = sum(values)
    idle = values[3] + values[4]

    return total, idle


def cpu_percent(before, after):
    total_delta = after[0] - before[0]
    idle_delta = after[1] - before[1]

    if total_delta <= 0:
        raise RuntimeError("Invalid CPU time delta")

    usage = 100 * (1 - idle_delta / total_delta)
    return round(max(0, min(100, usage)), 4)


def read_memory():
    fields = {}

    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        fields[key] = int(value.strip().split()[0])

    total = fields["MemTotal"]
    available = fields["MemAvailable"]

    if not 0 <= available <= total:
        raise RuntimeError("Invalid memory counters")

    return {
        "total_mib": round(total / 1024, 4),
        "available_mib": round(available / 1024, 4),
        "used_estimate_mib": round(
            (total - available) / 1024, 4
        ),
    }


def sample(duration, interval):
    if not 2 <= duration <= 30:
        raise ValueError("Duration must be 2-30 seconds")

    if not 0.1 <= interval <= 2:
        raise ValueError("Interval must be 0.1-2 seconds")

    count = round(duration / interval)

    before_cpu = read_cpu()
    initial_memory = read_memory()
    records = []

    started = time.monotonic()

    for index in range(count):
        time.sleep(interval)

        after_cpu = read_cpu()
        memory = read_memory()

        records.append({
            "sample": index + 1,
            "elapsed_seconds": round(
                time.monotonic() - started, 4
            ),
            "cpu_percent": cpu_percent(
                before_cpu, after_cpu
            ),
            "memory_used_estimate_mib":
                memory["used_estimate_mib"],
            "memory_available_mib":
                memory["available_mib"],
        })

        before_cpu = after_cpu

    cpu_values = [r["cpu_percent"] for r in records]
    memory_values = [
        r["memory_used_estimate_mib"] for r in records
    ]

    return {
        "schema_version": "1.0",
        "metric_scope": "WSL_guest_overall",
        "duration_requested_seconds": duration,
        "sample_interval_seconds": interval,
        "samples_collected": len(records),
        "mean_cpu_percent": round(
            statistics.mean(cpu_values), 4
        ),
        "peak_cpu_percent": max(cpu_values),
        "initial_memory_used_estimate_mib":
            initial_memory["used_estimate_mib"],
        "peak_memory_used_estimate_mib":
            max(memory_values),
        "memory_peak_change_mib": round(
            max(memory_values) -
            initial_memory["used_estimate_mib"], 4
        ),
        "samples": records,
    }


def check():
    assert cpu_percent(
        (100, 20), (200, 70)
    ) == 50.0

    cpu = read_cpu()
    memory = read_memory()

    assert cpu[0] > cpu[1] >= 0
    assert memory["total_mib"] > 0
    assert memory["available_mib"] >= 0

    print("RESOURCE_SAMPLER_SYNTAX=PASS")
    print("CPU_CALCULATION_TEST=PASS")
    print("PROC_STAT_ACCESS=PASS")
    print("PROC_MEMINFO_ACCESS=PASS")
    print("RESOURCE_SAMPLER_CHECK=PASS")
    print("TIMED_SAMPLES_EXECUTED=0")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", action="store_true")
    parser.add_argument("--duration", type=float, default=6)
    parser.add_argument("--interval", type=float, default=0.25)

    args = parser.parse_args()

    if args.sample:
        result = sample(args.duration, args.interval)
        print(json.dumps(result, indent=2))
    else:
        check()


if __name__ == "__main__":
    main()
