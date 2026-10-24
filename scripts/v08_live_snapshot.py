#!/usr/bin/env python3
"""V0.8 bounded nftables JSON snapshot of an already-owned isolated gateway.

--check       Offline source/plan inspection; never runs a command or uses sudo.
--capture     Root-staged, read-only capture of the gateway's forward chain.

The script does NOT create namespaces, send packets, enable logging, modify
firewall rules, or write evidence. Stdout for --capture is *only* the raw JSON
from nft -j. The unprivileged pipeline must parse and save it separately.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

STAGE = Path('/root/ztlab-v03-reviewed')
STAGED_SCRIPT = STAGE / 'v08_live_snapshot.py'
STATE = Path('/var/lib/ztlab-v03/state')
LOCK = Path('/var/lock/ztlab-v03.lock')
PLAN = Path('tests/v08_audit_plan.json')
EXPECTED_PLAN_SHA256 = 'd6602322a0e7f0f0533e8e5094112e19579d7565f5637db5c522d51cef5313d9'
NAMESPACES = ('zt-gw-ns', 'employee-ns', 'app-ns', 'data-ns')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


class SafetyError(RuntimeError):
    pass


def insist(ok, why):
    if not ok:
        raise SafetyError(why)


def regular_owned(path, mode):
    insist(not path.is_symlink(), f'Symlink refused: {path}')
    info = path.stat()
    insist(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
           stat.S_IMODE(info.st_mode) == mode,
           f'Unexpected root file ownership/mode: {path}')
    return info


def root_staging_preflight():
    insist(os.geteuid() == 0, 'Capture requires root-staged execution')
    insist(Path(__file__).absolute() == STAGED_SCRIPT and
           not STAGED_SCRIPT.is_symlink(), 'Execute only reviewed stage path')
    insist(STAGE.is_dir() and not STAGE.is_symlink(), 'Invalid stage directory')
    root = STAGE.stat()
    insist(root.st_uid == 0 and stat.S_IMODE(root.st_mode) == 0o700,
           'Root staging directory is not root:700')
    regular_owned(STAGED_SCRIPT, 0o700)
    regular_owned(STATE, 0o600)


def state_fields():
    contents = STATE.read_text(encoding='utf-8')
    values = {}
    for line in contents.splitlines():
        insist(re.fullmatch(r'(?:[A-Z][A-Z0-9_]*|NS_(?:zt_gw_ns|employee_ns|app_ns|data_ns)_INODE)=.*', line) is not None,
               'Malformed topology state record')
        key, value = line.split('=', 1)
        insist(key not in values, 'Duplicate topology state key')
        values[key] = value
    insist(values.get('OWNER') == 'zero-trust-network-security-lab',
           'Unexpected topology owner')
    insist(values.get('STATE_VERSION') == '1' and
           values.get('PHASE') == 'ACTIVE', 'Topology state not active')
    for name in NAMESPACES:
        key = 'NS_' + name.replace('-', '_') + '_INODE'
        expected = values.get(key, '')
        insist(re.fullmatch(r'\d+:\d+', expected) is not None,
               f'Missing namespace identity: {name}')
        ns_path = Path('/var/run/netns') / name
        insist(not ns_path.is_symlink(), f'Namespace symlink refused: {name}')
        try:
            ns_stat = ns_path.stat()
        except FileNotFoundError as exc:
            raise SafetyError(f'Missing namespace: {name}') from exc
        actual = f'{ns_stat.st_dev}:{ns_stat.st_ino}'
        insist(actual == expected, f'Namespace identity mismatch: {name}')


def trusted_executable(name):
    for directory in ('/usr/sbin', '/usr/bin', '/sbin', '/bin'):
        path = Path(directory) / name
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    raise SafetyError(f'Missing trusted system executable: {name}')


def command(*args):
    try:
        result = subprocess.run(args, check=True, capture_output=True,
                                text=True, timeout=10, env=ENV)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SafetyError(f'Bounded read-only command failed: {args[0]} {args[1:3]}') from exc
    return result.stdout


def acquire_lock():
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(LOCK), flags, 0o600)
    info = os.fstat(fd)
    insist(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
           not (info.st_mode & 0o022), 'Unsafe topology lock file')
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise SafetyError('Topology lock busy; snapshot refused') from exc
    return fd


def offline_check():
    insist(PLAN.is_file() and not PLAN.is_symlink(), 'Audit plan missing')
    raw = PLAN.read_bytes()
    insist(hashlib.sha256(raw).hexdigest() == EXPECTED_PLAN_SHA256,
           'Audit plan SHA-256 mismatch')
    data = json.loads(raw)
    insist(data.get('schema_version') == '1.0' and data.get('version') == 'V0.8' and
           data.get('rounds') == 3 and len(data.get('scenarios', [])) == 6,
           'Unexpected audit plan')
    assert 'nft -j' in __doc__
    print('V08_SNAPSHOT_SOURCE_CHECK=PASS')
    print('AUDIT_PLAN_SHA256=PASS')
    print('CAPTURE_MODE=REVIEWED_ROOT_ONLY')
    print('NETWORK_TESTS_EXECUTED=0')


def capture():
    root_staging_preflight()
    fd = acquire_lock()
    try:
        state_fields()
        ip = trusted_executable('ip')
        nft = trusted_executable('nft')
        sysctl = trusted_executable('sysctl')
        discovered = command(ip, 'netns', 'list')
        listed = {line.split()[0] for line in discovered.splitlines() if line.strip()}
        insist(listed == set(NAMESPACES), 'Unexpected namespaces in environment')
        forward = command(ip, 'netns', 'exec', 'zt-gw-ns',
                          sysctl, '-n', 'net.ipv4.ip_forward').strip()
        insist(forward == '1', 'Gateway IPv4 forwarding is disabled')
        raw = command(ip, 'netns', 'exec', 'zt-gw-ns',
                      nft, '-j', 'list', 'chain', 'inet', 'ztlab_v04', 'forward')
        doc = json.loads(raw)
        insist(isinstance(doc, dict) and isinstance(doc.get('nftables'), list),
               'Invalid nftables JSON output')
        # Full strict policy/rule parsing is intentionally done unprivileged by
        # the already reviewed v08_counter_parser.py from saved raw evidence.
        sys.stdout.write(json.dumps(doc, ensure_ascii=False, indent=2) + '\n')
    finally:
        os.close(fd)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    group = cli.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true')
    group.add_argument('--capture', action='store_true')
    args = cli.parse_args()
    if args.check:
        offline_check()
    else:
        capture()


if __name__ == '__main__':
    try:
        main()
    except (SafetyError, ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        print(f'V08_SNAPSHOT_ERROR={exc}', file=sys.stderr)
        sys.exit(1)
