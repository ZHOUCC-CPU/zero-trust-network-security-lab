#!/usr/bin/env python3
"""V0.8 one-case root-stage runner, isolated-network probes only.

--check: unprivileged offline scenario catalog check, no commands.
--execute CASE ROUND: one audited network case, capturing before/after nft JSON
on the same project-owned, segmented namespace topology. A single JSON object
is written to stdout upon success. Never run a user-writable copy as root.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

STAGE = Path('/root/ztlab-v03-reviewed')
SCRIPT = STAGE / 'v08_root_audit_case.py'
STATE = Path('/var/lib/ztlab-v03/state')
LOCK = Path('/var/lock/ztlab-v03.lock')
NAMES = ('zt-gw-ns', 'employee-ns', 'app-ns', 'data-ns')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
# scenario -> (source namespace, destination namespace, IP, protocol, port,
#              expected verdict, expected counter, expected body)
CASES = {
    'employee_to_app_tcp8080': ('employee-ns', 'app-ns', '10.200.20.2', 'tcp', 8080,
                                 'ALLOW', 'allow_emp_app', 'ZT_LAB_V04_HTTP_OK'),
    'app_to_data_tcp5432': ('app-ns', 'data-ns', '10.200.30.2', 'tcp', 5432,
                            'ALLOW', 'allow_app_data', 'ZT_LAB_V04_TCP5432_OK'),
    'employee_to_data_icmp': ('employee-ns', 'data-ns', '10.200.30.2', 'icmp', None,
                              'DENY', 'drop', None),
    'employee_to_data_tcp5432': ('employee-ns', 'data-ns', '10.200.30.2', 'tcp', 5432,
                                 'DENY', 'drop', 'ZT_LAB_V04_TCP5432_OK'),
    'employee_to_app_tcp8081': ('employee-ns', 'app-ns', '10.200.20.2', 'tcp', 8081,
                                'DENY', 'drop', 'ZT_LAB_V04_PORT8081'),
    'data_to_app_tcp8080': ('data-ns', 'app-ns', '10.200.20.2', 'tcp', 8080,
                            'DENY', 'drop', 'ZT_LAB_V04_HTTP_OK'),
}
HTTP_CLIENT = r'''
import sys, urllib.request
address,port,body=sys.argv[1:]
try:
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://'+address+':'+port+'/', timeout=3) as resp:
        ok=(resp.status==200 and resp.read(100).decode().strip()==body)
    if not ok:
        print('BAD_HTTP_RESPONSE', file=sys.stderr); sys.exit(2)
    print('HTTP_200_EXPECTED_BODY')
except Exception as exc:
    print('HTTP_CLIENT_ERROR='+type(exc).__name__, file=sys.stderr)
    sys.exit(3)
'''
TCP_DENY_CLIENT = r'''
import socket,sys
address,port=sys.argv[1:]
try:
    with socket.create_connection((address,int(port)),timeout=2):
        pass
except socket.timeout:
    print('TCP_CONNECT_TIMEOUT_BLOCKED')
    sys.exit(0)
except OSError as exc:
    print('INCONCLUSIVE_TCP_ERROR='+type(exc).__name__, file=sys.stderr)
    sys.exit(3)
print('UNEXPECTED_TCP_CONNECTION',file=sys.stderr)
sys.exit(2)
'''

class AuditError(RuntimeError):
    pass

def require(ok, reason):
    if not ok:
        raise AuditError(reason)

def run(args, timeout=10):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              env=ENV, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError(f'bounded command failure: {args[0]} ({type(exc).__name__})') from exc

def success(args, timeout=10):
    done = run(args, timeout)
    require(done.returncode == 0,
            f'command returned {done.returncode}: {args[:3]}: {done.stderr[-400:]}')
    return done.stdout

def owned(path, mode):
    require(not path.is_symlink(), f'symlink refused: {path}')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
            stat.S_IMODE(info.st_mode) == mode, f'unsafe root file: {path}')

def acquire_lock():
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(LOCK, flags)
    st = os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
            not (st.st_mode & 0o022), 'unsafe lock')
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise AuditError('topology lock busy') from exc
    return fd

def state_preflight():
    require(os.geteuid() == 0, 'must execute root-staged')
    require(Path(__file__).absolute() == SCRIPT, 'wrong script path')
    require(STAGE.is_dir() and not STAGE.is_symlink(), 'unsafe stage')
    st = STAGE.stat()
    require(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700, 'unsafe stage mode')
    owned(SCRIPT, 0o700)
    owned(STATE, 0o600)
    fields = {}
    for line in STATE.read_text(encoding='utf-8').splitlines():
        require(re.fullmatch(r'(?:[A-Z][A-Z0-9_]*|NS_(?:zt_gw_ns|employee_ns|app_ns|data_ns)_INODE)=.*', line) is not None,
                'malformed state record')
        key, value = line.split('=', 1)
        require(key not in fields, 'duplicate state record')
        fields[key] = value
    require(fields.get('STATE_VERSION') == '1' and
            fields.get('PHASE') == 'ACTIVE' and
            fields.get('OWNER') == 'zero-trust-network-security-lab',
            'unexpected topology state')
    require(re.fullmatch('[0-9a-f-]{36}', fields.get('TOKEN', '')) is not None,
            'missing deployment token')
    for name in NAMES:
        ns_path = Path('/var/run/netns') / name
        require(not ns_path.is_symlink(), 'namespace symlink')
        ns_stat = ns_path.stat()
        expected = fields.get('NS_' + name.replace('-', '_') + '_INODE')
        require(expected == f'{ns_stat.st_dev}:{ns_stat.st_ino}',
                f'namespace identity mismatch: {name}')
    listed = success(['/usr/sbin/ip', 'netns', 'list']).splitlines()
    require({line.split()[0] for line in listed if line.strip()} == set(NAMES),
            'unexpected namespace inventory')
    forward = success(['/usr/sbin/ip', 'netns', 'exec', 'zt-gw-ns',
                       '/usr/sbin/sysctl', '-n', 'net.ipv4.ip_forward']).strip()
    require(forward == '1', 'gateway forwarding disabled')
    return fields['TOKEN']

def snapshot():
    raw = success(['/usr/sbin/ip', 'netns', 'exec', 'zt-gw-ns', '/usr/sbin/nft',
                   '-j', 'list', 'chain', 'inet', 'ztlab_v04', 'forward'])
    doc = json.loads(raw)
    require(isinstance(doc, dict) and isinstance(doc.get('nftables'), list),
            'unexpected nft JSON')
    chains = [e['chain'] for e in doc['nftables'] if isinstance(e, dict) and 'chain' in e]
    rules = [e['rule'] for e in doc['nftables'] if isinstance(e, dict) and 'rule' in e]
    require(len(chains) == 1 and chains[0].get('policy') == 'drop' and
            len(rules) == 4, 'unexpected firewall chain/rule count')
    return doc

def check_listening(ns, ip, port):
    result = success(['/usr/sbin/ip', 'netns', 'exec', ns,
                      '/usr/bin/ss', '-H', '-ltn', f'sport = :{port}'])
    return any(ip + ':' + str(port) in line for line in result.splitlines())

def start_server(ns, ip, port, body, temp_dir):
    require(not check_listening(ns, ip, port), 'unexpected existing port listener')
    directory = temp_dir / f'service_{port}'
    directory.mkdir(mode=0o700)
    (directory / 'index.html').write_text(body + '\n', encoding='utf-8')
    proc = subprocess.Popen(
        ['/usr/sbin/ip', 'netns', 'exec', ns, '/usr/bin/python3', '-I',
         '-m', 'http.server', str(port), '--bind', ip, '--directory', str(directory)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV,
        start_new_session=True,
    )
    try:
        for _ in range(30):
            if proc.poll() is not None:
                break
            if check_listening(ns, ip, port):
                return proc
            time.sleep(0.1)
        raise AuditError('target service not ready')
    except BaseException:
        stop_server(proc)
        raise

def stop_server(proc):
    if proc is None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)

def behavior(case_id, round_number, case):
    src, dst, addr, protocol, port, verdict, counter, body = case
    if protocol == 'icmp':
        done = run(['/usr/sbin/ip', 'netns', 'exec', src, '/usr/bin/ping',
                    '-n', '-c', '2', '-W', '1', addr], timeout=8)
        combined = done.stdout + done.stderr
        require(done.returncode == 1 and
                re.search(r'2 packets transmitted, 0 received', combined) and
                '100% packet loss' in combined,
                f'ICMP DENY inconclusive (status={done.returncode}): {combined[-200:]}')
        detail = '2 ICMP echo packets transmitted; no replies; expected drop counter increment'
    elif verdict == 'ALLOW':
        done = run(['/usr/sbin/ip', 'netns', 'exec', src,
                    '/usr/bin/python3', '-I', '-c', HTTP_CLIENT,
                    addr, str(port), body], timeout=8)
        require(done.returncode == 0 and 'HTTP_200_EXPECTED_BODY' in done.stdout,
                f'ALLOW HTTP failed ({done.returncode}): {done.stderr[-200:]}')
        detail = 'HTTP 200 and expected response body'
    else:
        done = run(['/usr/sbin/ip', 'netns', 'exec', src,
                    '/usr/bin/python3', '-I', '-c', TCP_DENY_CLIENT,
                    addr, str(port)], timeout=7)
        require(done.returncode == 0 and 'TCP_CONNECT_TIMEOUT_BLOCKED' in done.stdout,
                f'TCP DENY inconclusive ({done.returncode}): {done.stderr[-200:]}')
        detail = 'TCP connection timed out; target service confirmed listening'
    return {
        'scenario_id': case_id, 'round': round_number, 'observed_behavior': verdict,
        'result': 'PASS', 'exit_code': 0, 'detail': detail,
        'underlying_probe_exit_code': done.returncode,
    }

def execute(case_id, round_number):
    def interrupted(signum, frame):
        raise AuditError('audit case interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    lock_fd = acquire_lock()
    try:
        token = state_preflight()
        case = CASES[case_id]
        src, dst, address, protocol, port, verdict, counter, body = case
        proc = None
        with tempfile.TemporaryDirectory(prefix='ztlab-v08-case-', dir='/tmp') as directory:
            try:
                if protocol == 'tcp':
                    proc = start_server(dst, address, port, body, Path(directory))
                before = snapshot()
                observed = behavior(case_id, round_number, case)
                after = snapshot()
            finally:
                stop_server(proc)
        print(json.dumps({
            'case_id': case_id, 'round': round_number,
            'deployment_token': token,
            'before': before, 'after': after, 'behavior': observed,
        }, ensure_ascii=False))
    finally:
        os.close(lock_fd)

def main():
    cli = argparse.ArgumentParser(description=__doc__)
    group = cli.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true')
    group.add_argument('--execute', nargs=2, metavar=('CASE_ID','ROUND'))
    args = cli.parse_args()
    if args.check:
        require(len(CASES) == 6 and len(set(CASES)) == 6, 'scenario catalog')
        print('V08_ROOT_CASE_SOURCE_CHECK=PASS')
        print('NETWORK_TESTS_EXECUTED=0')
        return
    case_id, round_text = args.execute
    require(case_id in CASES, 'unknown case')
    require(round_text in ('1', '2', '3'), 'invalid round')
    execute(case_id, int(round_text))

if __name__ == '__main__':
    try:
        main()
    except (AuditError, OSError, ValueError, TypeError, KeyError,
            subprocess.SubprocessError) as exc:
        print(f'V08_CASE_ERROR={exc}', file=sys.stderr)
        sys.exit(1)
