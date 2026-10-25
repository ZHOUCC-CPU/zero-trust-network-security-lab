#!/usr/bin/env python3
"""V0.9 read-only lab residue check. No cleanup or topology changes."""
import argparse
import fcntl
import os
import stat
import json
import subprocess
import sys

NAMESPACES = frozenset({"zt-gw-ns", "employee-ns", "app-ns", "data-ns"})
HOST_IFACES = frozenset({
    "ztlab-emp-gw", "ztlab-app-gw", "ztlab-data-gw",
    "ztlab-gw-emp", "ztlab-gw-app", "ztlab-gw-data",
    "gw-emp", "gw-app", "gw-data", "emp-gw", "app-gw", "data-gw",
})
STATE = "/var/lib/ztlab-v03/state"
LOCK = "/var/lock/ztlab-v03.lock"


def findings(namespace_text, links, state_present):
    if not isinstance(namespace_text, str) or not isinstance(links, list):
        raise ValueError("invalid namespace or interface data")
    namespaces = {line.split()[0] for line in namespace_text.splitlines() if line.strip()}
    names = set()
    for link in links:
        if not isinstance(link, dict) or not isinstance(link.get("ifname"), str):
            raise ValueError("invalid ip -j link record")
        names.add(link["ifname"])
    return (sorted(namespaces & NAMESPACES),
            sorted(name for name in names if name in HOST_IFACES or name.startswith("ztlab-")),
            bool(state_present))


def checked(argv, permitted=(0,)):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    if result.returncode not in permitted:
        raise RuntimeError(f"command failed (exit {result.returncode}): {' '.join(argv)}; {result.stderr.strip()}")
    if result.stderr.strip():
        raise RuntimeError(f"command diagnostic: {' '.join(argv)}; {result.stderr.strip()}")
    return result


def privileged_state_exists():
    checked(["sudo", "-n", "true"])
    # Both tests are required: -e is false for broken symlinks, -L detects them.
    exists = checked(["sudo", "-n", "test", "-e", STATE], (0, 1)).returncode == 0
    symlink = checked(["sudo", "-n", "test", "-L", STATE], (0, 1)).returncode == 0
    return exists or symlink


def self_test():
    assert findings("", [{"ifname": "lo"}, {"ifname": "eth0"}], False) == ([], [], False)
    assert findings("app-ns (id: 2)\n", [{"ifname": "ztlab-emp-gw"}], True) == (
        ["app-ns"], ["ztlab-emp-gw"], True)
    assert findings("", [{"ifname": "emp-gw"}], False) == ([], ["emp-gw"], False)
    try:
        findings("", [{"name": "missing-ifname"}], False)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid interface record accepted")
    print("V09_RESOURCE_INTEGRITY_SELF_TEST=PASS")
    print("NETWORK_TESTS_EXECUTED=0")


def live_check():
    # Shared lock prevents snapshots while deployment / cleanup holds an exclusive lock.
    fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as lock_file:
        info = os.fstat(lock_file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("unsafe or writable project lock")
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        namespace_text = checked(["ip", "netns", "list"]).stdout
        links = json.loads(checked(["ip", "-j", "link", "show"]).stdout)
        state_present = privileged_state_exists()
    ns, ifaces, state = findings(namespace_text, links, state_present)
    print("PROJECT_NAMESPACES=" + (",".join(ns) if ns else "NONE"))
    print("SUSPECT_HOST_INTERFACES=" + (",".join(ifaces) if ifaces else "NONE"))
    print("PROJECT_STATE_PRESENT=" + ("YES" if state else "NO"))
    if ns or ifaces or state:
        print("V09_RESOURCE_INTEGRITY=FAIL")
        raise SystemExit("STOP: possible project residue; inspect manually (no automatic deletion)")
    print("V09_RESOURCE_INTEGRITY=PASS")
    print("NETWORK_TESTS_EXECUTED=0")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        self_test() if args.self_test else live_check()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"V09_RESOURCE_INTEGRITY_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
