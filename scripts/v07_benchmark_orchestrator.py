#!/usr/bin/env python3
"""V0.7 controlled baseline/segmented performance benchmark orchestrator.

Default: offline, read-only source/config validation (--check).
--execute is an explicit opt-in for a privileged, isolated network experiment.
--verify DIR revalidates a saved session without executing networking operations.

Use as the normal Ubuntu user. Root commands invoke only previously reviewed,
root-owned scripts and binaries; never sudo-run files from a Windows mount.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import threading
import time

PROJECT = Path(__file__).resolve().parent.parent
ROOT_DIR = Path('/root/ztlab-v03-reviewed')
STATE = '/var/lib/ztlab-v03/state'
EVIDENCE = PROJECT / 'evidence/v07_runs'
REPORT = PROJECT / 'reports/V0.7_EXPERIMENT_REPORT.md'
PLAN_FILE = PROJECT / 'tests/v07_benchmark_plan.json'
STAGED = ('v07_root_benchmark_runner.sh', 'v07_tcp_latency.py',
          'v07_iperf3_throughput.py')
ROOT_SCRIPTS = ('topology_up.sh', 'check_topology.sh',
                'load_v04_policy.sh', 'topology_down.sh')
FLOWS = {
    'employee_to_app_tcp8080': ('employee-ns', 'app-ns', '10.200.20.2', 8080),
    'app_to_data_tcp5432': ('app-ns', 'data-ns', '10.200.30.2', 5432),
}
CONDITIONS = ('baseline', 'segmented')
KINDS = ('latency', 'throughput')
ROUNDS = 3
INTERVAL = 0.25

sys.path.insert(0, str(PROJECT / 'scripts'))
from v07_resource_metrics import read_cpu, read_memory, cpu_percent  # noqa: E402


def utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save(path: Path, content: str) -> None:
    # Exclusive creation prevents overwriting or following an existing symlink.
    with path.open('x', encoding='utf-8', newline='') as handle:
        handle.write(content)


def save_json(path: Path, data: object) -> None:
    save(path, json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def run(args: list[str], deadline: int = 60) -> tuple[int, str, str, float]:
    start = time.monotonic()
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              errors='replace', timeout=deadline, check=False)
        return proc.returncode, proc.stdout, proc.stderr, time.monotonic()-start
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or b''
        err = exc.stderr or b''
        if isinstance(out, bytes):
            out = out.decode('utf-8', 'replace')
        if isinstance(err, bytes):
            err = err.decode('utf-8', 'replace')
        return 124, out, err + '\nOUTER_TIMEOUT', time.monotonic()-start
    except OSError as exc:
        return 127, '', repr(exc), time.monotonic()-start


def required(args: list[str], label: str, deadline: int = 60) -> str:
    rc, out, err, _ = run(args, deadline)
    if rc != 0:
        raise RuntimeError(f'{label}: exit={rc}, {err[-500:]}, {out[-500:]}')
    return out


def verify_plan() -> dict:
    data = json.loads(PLAN_FILE.read_text(encoding='utf-8'))
    if data['conditions'] != list(CONDITIONS) or data['rounds_per_condition'] != ROUNDS:
        raise RuntimeError('Unexpected conditions or round count')
    configured = {
        f['id']: (f['source_namespace'], f['destination_namespace'],
                  f['destination_ip'], f['port']) for f in data['flows']
    }
    if configured != FLOWS or len(data['flows']) != 2:
        raise RuntimeError('Flow matrix does not match fixed allow-list')
    t = data['throughput']
    l = data['latency']
    if not (t['tool'] == 'iperf3' and t['protocol'] == 'TCP'
            and t['duration_seconds'] == 5 and t['parallel_streams'] == 1
            and t['target_bitrate_mbps'] == 50
            and l['method'] == 'TCP_CONNECT'
            and l['probes_per_flow'] == 30 and l['timeout_seconds'] == 2):
        raise RuntimeError('Unexpected measurement parameters')
    safety = data['safety']
    if not all(safety[k] is True for k in ('isolated_namespaces_only',
           'no_host_firewall_modification', 'no_external_traffic',
           'no_background_daemon')):
        raise RuntimeError('Safety flags are not enabled')
    return data


def local_check() -> dict:
    plan = verify_plan()
    for name in STAGED + ('v07_resource_metrics.py',):
        path = PROJECT / 'scripts' / name
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f'Missing or symlinked local script: {name}')
        source = path.read_text(encoding='utf-8')
        if name.endswith('.py'):
            compile(source, str(path), 'exec')
        elif required(['bash', '-n', str(path)], 'Bash syntax'):
            raise RuntimeError('Unexpected bash -n stdout')
    if not (PROJECT / 'docs/V0.7_BENCHMARK_DESIGN.md').is_file():
        raise RuntimeError('Missing experiment design')
    if not (PROJECT / 'scripts/v07_root_benchmark_runner.sh').read_text(
            encoding='utf-8').count('flock -x -n 9') == 1:
        raise RuntimeError('Root runner exclusive lock not found')
    if not (PROJECT / 'scripts/v07_root_benchmark_runner.sh').read_text(
            encoding='utf-8').count('Cannot inspect listener state in $dst') == 1:
        raise RuntimeError('Expected port preflight safety patch missing')
    print('V07_CONFIGURATION=PASS')
    print('V07_COMPONENT_SYNTAX=PASS')
    print('V07_ROOT_RUNNER_LOCK_AND_PORT_PATCH=PASS')
    print('V07_PLAN=2_CONDITIONS_3_ROUNDS_2_FLOWS')
    print('NETWORK_TESTS_EXECUTED=0')
    return plan


def check_root() -> None:
    if os.geteuid() == 0:
        raise RuntimeError('Run the orchestrator as your normal WSL user, not root')
    required(['sudo', '-n', 'true'], 'Cached sudo authorization', 10)
    owner = required(['sudo', '-n', 'stat', '-c', '%u:%a', str(ROOT_DIR)],
                     'Root staging directory', 10).strip()
    if owner != '0:700':
        raise RuntimeError('Unexpected root staging directory ownership/mode')
    for name in STAGED:
        target = ROOT_DIR / name
        rc, _, _, _ = run(['sudo', '-n', 'test', '-L', str(target)], 10)
        if rc != 1:
            raise RuntimeError(f'Unexpected root staged symlink/test failure: {name}')
        meta = required(['sudo', '-n', 'stat', '-c', '%u:%a', str(target)],
                        f'Root script metadata {name}', 10).strip()
        if meta != '0:700':
            raise RuntimeError(f'Invalid root stage permissions: {name}: {meta}')
        root_hash = required(['sudo', '-n', 'sha256sum', str(target)],
                             f'Root script digest {name}', 10).split()[0]
        source_hash = sha((PROJECT / 'scripts' / name).read_bytes())
        if root_hash != source_hash:
            raise RuntimeError(f'Root stage differs from reviewed source: {name}')
    for name in ROOT_SCRIPTS:
        target = ROOT_DIR / name
        if required(['sudo', '-n', 'stat', '-c', '%u:%a', str(target)],
                    f'Reviewed root tool {name}', 10).strip() != '0:700':
            raise RuntimeError(f'Invalid reviewed tool ownership/mode: {name}')
    if required(['sudo', '-n', 'ip', 'netns', 'list'], 'Existing namespace check', 10).strip():
        raise RuntimeError('Existing network namespaces; refusing deployment')
    rc, _, _, _ = run(['sudo', '-n', 'test', '-e', STATE], 10)
    if rc != 1:
        raise RuntimeError('Existing state file or failed check; refusing deployment')
    print('ROOT_STAGING_AND_PREDEPLOY_CHECK=PASS', flush=True)


def collect_resource_metrics(args: list[str], deadline: int) -> tuple[int, str, str, float, dict]:
    # Sample overall WSL guest resource usage concurrently with the real probe.
    stop = threading.Event()
    samples: list[dict] = []
    errors: list[str] = []
    initial = read_memory()

    def sampler() -> None:
        try:
            prev = read_cpu()
            while not stop.wait(INTERVAL):
                cur = read_cpu()
                mem = read_memory()
                samples.append({
                    'cpu_percent': cpu_percent(prev, cur),
                    'memory_used_estimate_mib': mem['used_estimate_mib'],
                    'memory_available_mib': mem['available_mib'],
                })
                prev = cur
        except Exception as exc:
            errors.append(str(exc))

    worker = threading.Thread(target=sampler, daemon=True)
    worker.start()
    try:
        rc, out, err, elapsed = run(args, deadline)
    finally:
        stop.set()
        worker.join(timeout=2)

    values = [r['cpu_percent'] for r in samples]
    memory = [r['memory_used_estimate_mib'] for r in samples]
    metrics = {
        'scope': 'WSL_guest_overall',
        'sample_interval_seconds': INTERVAL,
        'samples_collected': len(samples),
        'mean_cpu_percent': round(statistics.mean(values), 5) if values else None,
        'peak_cpu_percent': max(values) if values else None,
        'initial_memory_used_estimate_mib': initial['used_estimate_mib'],
        'peak_memory_used_estimate_mib': max(memory) if memory else None,
        'samples': samples,
        'sampler_errors': errors,
    }
    return rc, out, err, elapsed, metrics


def verify_measurement(result: dict, kind: str, flow: str) -> None:
    if result.get('flow_id') != flow:
        raise RuntimeError('Probe returned incorrect flow')
    src, _, dst, port = FLOWS[flow]
    if result.get('source_namespace') != src or result.get('destination_ip') != dst \
            or result.get('destination_port') != port:
        raise RuntimeError('Probe returned unexpected endpoint')
    if kind == 'latency':
        if result.get('requested_probes') != 30 or result.get('successful_probes') != 30 \
                or result.get('failed_probes') != 0 or len(result.get('latency_ms', [])) != 30:
            raise RuntimeError('Latency probe count or failures invalid')
        for val in result['latency_ms']:
            if not isinstance(val, (int, float)) or not math.isfinite(val) or val <= 0:
                raise RuntimeError('Invalid latency value')
        for field in ('mean_ms', 'median_ms', 'p95_ms'):
            val = result.get(field)
            if not isinstance(val, (int, float)) or not math.isfinite(val) or val <= 0:
                raise RuntimeError(f'Invalid latency statistic: {field}')
    else:
        if result.get('duration_seconds') != 5 or result.get('target_bitrate_mbps') != 50 \
                or result.get('result') != 'PASS':
            raise RuntimeError('Unexpected iperf3 configuration/result')
        for field in ('measured_send_mbps', 'measured_receive_mbps'):
            val = result.get(field)
            if not isinstance(val, (int, float)) or not math.isfinite(val) or val <= 0:
                raise RuntimeError(f'Invalid throughput field: {field}')


def snapshot(directory: Path, filename: str, args: list[str], timeout: int = 80) -> float:
    rc, out, err, elapsed = run(args, timeout)
    save(directory / filename, f'EXIT_CODE={rc}\nELAPSED_SECONDS={elapsed:.6f}\n'
         f'STDOUT:\n{out}\nSTDERR:\n{err}\n')
    if rc != 0:
        raise RuntimeError(f'{filename}: exit={rc}; {err[-400:]} {out[-400:]}')
    return elapsed


def check_cleanup() -> bool:
    try:
        if required(['sudo', '-n', 'ip', 'netns', 'list'], 'Residual namespaces', 12).strip():
            return False
        rc, _, _, _ = run(['sudo', '-n', 'test', '-e', STATE], 10)
        if rc != 1:
            return False
        for iface in ('gw-emp', 'gw-app', 'gw-data', 'emp-gw', 'app-gw', 'data-gw'):
            rc, _, _, _ = run(['ip', 'link', 'show', 'dev', iface], 10)
            if rc == 0:
                return False
        return True
    except RuntimeError:
        return False


def owned_state() -> bool:
    # Do NOT automatically clean up if ownership/identity cannot be established.
    try:
        check = required(['sudo', '-n', 'stat', '-c', '%u:%a', STATE],
                         'State metadata', 10).strip()
        if check != '0:600':
            return False
        content = required(['sudo', '-n', 'cat', STATE], 'State read', 10)
        entries = dict(line.split('=', 1) for line in content.splitlines() if '=' in line)
        if entries.get('OWNER') != 'zero-trust-network-security-lab' \
                or entries.get('PHASE') != 'ACTIVE' \
                or entries.get('STATE_VERSION') != '1':
            return False
        for ns in ('zt-gw-ns', 'employee-ns', 'app-ns', 'data-ns'):
            actual = required(['sudo', '-n', 'stat', '-Lc', '%d:%i',
                               f'/var/run/netns/{ns}'], f'Identity {ns}', 10).strip()
            if entries.get('NS_' + ns.replace('-', '_') + '_INODE') != actual:
                return False
        return True
    except (RuntimeError, ValueError):
        return False


def run_probes(directory: Path, condition: str, records: list[dict]) -> None:
    for round_index in range(1, ROUNDS + 1):
        for kind in KINDS:
            for flow in FLOWS:
                prefix = f'{condition}_r{round_index:02d}_{kind}_{flow}'
                print(f'PROBE_START={prefix}', flush=True)
                args = ['sudo', '-n', 'timeout', '--signal=TERM',
                        '--kill-after=3s', '30s', 'bash',
                        str(ROOT_DIR / 'v07_root_benchmark_runner.sh'),
                        condition, kind, flow]
                rc, out, err, elapsed, resource = collect_resource_metrics(args, 40)
                raw_out = directory / (prefix + '.stdout.json')
                raw_err = directory / (prefix + '.stderr.txt')
                save(raw_out, out)
                save(raw_err, err)
                save_json(directory / (prefix + '.resources.json'), resource)
                if rc != 0:
                    raise RuntimeError(f'{prefix}: runner exit={rc}; stderr={err[-600:]}')
                try:
                    measured = json.loads(out)
                except json.JSONDecodeError as exc:
                    raise RuntimeError(f'{prefix}: invalid JSON: {exc}') from exc
                verify_measurement(measured, kind, flow)
                if resource['sampler_errors'] or not resource['samples_collected']:
                    raise RuntimeError(f'{prefix}: insufficient/failed resource sampling')
                records.append({
                    'condition': condition, 'round': round_index, 'kind': kind,
                    'flow': flow, 'elapsed_seconds': round(elapsed, 5),
                    'probe_result': measured, 'resource_metrics': {
                        k: v for k, v in resource.items() if k != 'samples'
                    }, 'log_file': str(raw_out.relative_to(PROJECT)),
                    'log_sha256': sha(raw_out.read_bytes()),
                })
                print(f'PROBE_PASS={prefix}', flush=True)


def report(records: list[dict], deploy_s: float | None,
           cleanup_s: float | None, directory: Path, evidence_bytes: int) -> str:
    lines = [
        '# V0.7 Experiment Report',
        '## Performance and Resource Assessment', '',
        '**Project:** Zero Trust Network Security Lab',
        f'**Generated (UTC):** {utc()}',
        '**Result:** PASS — 24/24 completed flow-metric runs', '',
        '## Scope and methodology',
        'Same authorized flows in sequential baseline and segmented conditions;',
        'three rounds per condition, two flows, TCP connection latency (30 probes)',
        'and iperf3 TCP at 50 Mbit/s target (5 seconds, one stream).',
        'The 50 Mbit/s target is not an estimate of maximum throughput.',
        'WSL CPU and memory observations describe overall guest usage.', '',
        '## Per-flow comparative measurements', '',
        '| Flow | Metric | Baseline mean | Segmented mean | Difference (segmented-baseline) |',
        '|---|---|---:|---:|---:|',
    ]
    for flow in FLOWS:
        for kind in KINDS:
            key = 'median_ms' if kind == 'latency' else 'measured_receive_mbps'
            group = {condition: [r['probe_result'][key] for r in records
                                 if r['condition'] == condition and r['kind'] == kind
                                 and r['flow'] == flow] for condition in CONDITIONS}
            a, b = (statistics.mean(group[cond]) for cond in CONDITIONS)
            unit = 'ms (median TCP connect)' if kind == 'latency' else 'Mbit/s (receiver)'
            lines.append(f'| `{flow}` | {unit} | {a:.5f} | {b:.5f} | {b-a:+.5f} |')
    lines += ['', '## WSL guest-wide resource observations', '',
              '| Condition | Mean of per-run CPU means (%) | Highest sampled used memory (MiB) |',
              '|---|---:|---:|']
    for condition in CONDITIONS:
        subset = [r['resource_metrics'] for r in records if r['condition'] == condition]
        cpu_mean = statistics.mean(r['mean_cpu_percent'] for r in subset)
        memory_peak = max(r['peak_memory_used_estimate_mib'] for r in subset)
        lines.append(f'| {condition} | {cpu_mean:.5f} | {memory_peak:.5f} |')
    lines += ['', 'These figures include all guest activity, and are not isolated',
              'measurements of firewall or test-process overhead.', '']
    lines += ['', '## Operational measurements', '',
              f'- Single topology deployment duration: {deploy_s:.5f} s.',
              f'- Single topology cleanup duration: {cleanup_s:.5f} s.',
              '- These are individual measurements, not three repetitions per condition.', '',
              '## Evidence', '',
              f'- Session: `{directory.relative_to(PROJECT)}`',
              '- Per-run stdout, stderr, and WSL resource samples; JSON summary and CSV.',
              '- Source log SHA-256 digests are recorded and cross-checked offline.',
              f'- Session evidence file size at report creation: {evidence_bytes} bytes.', '',
              '## Limitations', '',
              '- The test order is not randomized; host activity and WSL scheduling may bias results.',
              '- CPU and memory are system-wide and cannot isolate nftables overhead.',
              '- Connection latency is not ICMP round-trip latency.',
              '- Sequential tests and low sample counts do not support causal or production claims.',
              '- TCP target bitrate is offered load, not peak capacity or guaranteed hard limiting.',
              '- Results apply to this isolated namespace topology, not real user identities.', '',
              '## Conclusion', '',
              'The measurements describe differences under the chosen bounded laboratory',
              'conditions; no production-grade Zero Trust or general throughput claim is made.',
    ]
    return '\n'.join(lines) + '\n'


def verify_saved(directory: Path) -> None:
    summary_path = directory / 'summary.json'
    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    if not summary.get('all_passed') or not summary.get('cleanup_verified'):
        raise RuntimeError('Session not marked complete with verified cleanup')
    records = summary['measurements']
    if len(records) != 24:
        raise RuntimeError(f'Expected 24 flow-metric runs, saw {len(records)}')
    expected = {(c, r, k, f) for c in CONDITIONS for r in range(1, ROUNDS + 1)
                for k in KINDS for f in FLOWS}
    observed = {(r['condition'], r['round'], r['kind'], r['flow']) for r in records}
    if expected != observed:
        raise RuntimeError('Incomplete or duplicated measurement matrix')
    with (directory / 'measurements.csv').open(newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    if len(rows) != len(expected):
        raise RuntimeError('CSV row count mismatch')
    for record in records:
        logfile = PROJECT / record['log_file']
        data = logfile.read_bytes()
        if sha(data) != record['log_sha256']:
            raise RuntimeError(f'Log hash mismatch: {logfile}')
        verify_measurement(json.loads(data), record['kind'], record['flow'])
        key = (record['condition'], record['round'], record['kind'], record['flow'])
        count = sum((row['condition'], int(row['round']), row['kind'], row['flow']) == key
                    and row['log_sha256'] == record['log_sha256'] for row in rows)
        if count != 1:
            raise RuntimeError(f'CSV differs from log record: {key}')
    print('V07_LOG_SHA256_AND_CSV_CHECK=PASS')
    print('V07_VERIFIED_FLOW_METRIC_RUNS=24/24')


def execute(plan: dict) -> int:
    if REPORT.exists() or REPORT.is_symlink():
        print('ERROR: existing V0.7 report; refusing overwrite', file=sys.stderr)
        return 2
    check_root()
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    directory = EVIDENCE / ('run_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                            + '_' + str(os.getpid()))
    directory.mkdir(mode=0o700)
    print('SESSION_DIR=' + str(directory.relative_to(PROJECT)), flush=True)
    issues: list[str] = []
    records: list[dict] = []
    deploy_s: float | None = None
    cleanup_s: float | None = None
    cleaned = False
    deployment_attempted = False
    try:
        deployment_attempted = True
        deploy_s = snapshot(directory, 'topology_deployment.txt',
            ['sudo','-n','timeout','--signal=TERM','--kill-after=10s','60s',
             'bash',str(ROOT_DIR / 'topology_up.sh')], 75)
        validated = required(['sudo','-n','timeout','60s','bash',
                              str(ROOT_DIR / 'check_topology.sh')],
                             'V0.3 topology validation', 70)
        save(directory / 'topology_validation.txt', validated)
        if 'SUMMARY|topology_failures|0' not in validated:
            raise RuntimeError('Topology validator failed to confirm success')
        baseline_tables = required(['sudo','-n','ip','netns','exec','zt-gw-ns',
                                    'nft','list','tables'], 'Baseline tables', 15)
        save(directory / 'baseline_tables.txt', baseline_tables)
        if baseline_tables.strip():
            raise RuntimeError('Baseline gateway has existing nftables tables')
        print('BASELINE_READY=PASS', flush=True)
        run_probes(directory, 'baseline', records)
        snapshot(directory, 'policy_load.txt',
                 ['sudo','-n','timeout','45s','bash',str(ROOT_DIR / 'load_v04_policy.sh')], 55)
        rules = required(['sudo','-n','ip','netns','exec','zt-gw-ns','nft',
                          'list','chain','inet','ztlab_v04','forward'],
                         'Segmented policy inspection', 15)
        save(directory / 'segmented_rules.txt', rules)
        for marker in ('policy drop;', 'ct state established,related',
                       'iifname "gw-emp" oifname "gw-app"',
                       'iifname "gw-app" oifname "gw-data"'):
            if marker not in rules:
                raise RuntimeError(f'Missing rule marker: {marker}')
        print('SEGMENTED_READY=PASS', flush=True)
        run_probes(directory, 'segmented', records)
    except (RuntimeError, ValueError, OSError, KeyboardInterrupt) as exc:
        issues.append(str(exc))
        print(f'EXPERIMENT_ERROR={exc}', file=sys.stderr, flush=True)
    finally:
        # If deployment only partially succeeded, do not guess ownership.
        if deployment_attempted:
            if owned_state():
                rc, out, err, elapsed = run(['sudo','-n','timeout','--signal=TERM',
                    '--kill-after=10s','90s','bash',str(ROOT_DIR / 'topology_down.sh')], 105)
                cleanup_s = elapsed
                save(directory / 'cleanup.txt', f'EXIT_CODE={rc}\n{out}\n{err}\n')
                cleaned = rc == 0 and check_cleanup()
                if not cleaned:
                    issues.append('Owned topology cleanup failed or residual resources detected')
            elif check_cleanup():
                cleaned = True
                save(directory / 'cleanup.txt', 'NO_OWNED_TOPOLOGY_REMAINS\n')
            else:
                save(directory / 'cleanup.txt',
                     'MANUAL_RECOVERY_REQUIRED: ownership/identity not proven; cleanup refused\n')
                issues.append('Manual recovery required; residual or incomplete state remains')
        else:
            cleaned = check_cleanup()
    passed = len(records) == 24 and not issues and cleaned and deploy_s is not None \
             and cleanup_s is not None
    if records:
        csv_path = directory / 'measurements.csv'
        with csv_path.open('x', encoding='utf-8', newline='') as handle:
            fields = ['condition','round','kind','flow','elapsed_seconds',
                      'mean_cpu_percent','peak_memory_used_estimate_mib',
                      'measurement_value','log_file','log_sha256']
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for rec in records:
                p = rec['probe_result']
                writer.writerow({
                    'condition': rec['condition'], 'round': rec['round'],
                    'kind': rec['kind'], 'flow': rec['flow'],
                    'elapsed_seconds': rec['elapsed_seconds'],
                    'mean_cpu_percent': rec['resource_metrics']['mean_cpu_percent'],
                    'peak_memory_used_estimate_mib': rec['resource_metrics']['peak_memory_used_estimate_mib'],
                    'measurement_value': p['median_ms'] if rec['kind']=='latency'
                                          else p['measured_receive_mbps'],
                    'log_file': rec['log_file'], 'log_sha256': rec['log_sha256'],
                })
    evidence_before_summary = sum(path.stat().st_size for path in directory.rglob('*')
                                  if path.is_file())
    summary = {'schema_version':'1.0', 'generated_utc':utc(),
               'session_directory':str(directory.relative_to(PROJECT)),
               'conditions':list(CONDITIONS),'rounds_per_condition':ROUNDS,
               'measurements':records,'total_measurements':len(records),
               'topology_deployment_seconds':deploy_s,
               'topology_cleanup_seconds':cleanup_s,
               'evidence_bytes_excluding_summary_json':evidence_before_summary,
               'cleanup_verified':cleaned,'issues':issues,'all_passed':passed,
               'caveat':'WSL guest-wide CPU/memory; sequential conditions; fixed 50 Mbit/s target'}
    save_json(directory / 'summary.json', summary)
    if not passed:
        print('V07_EXPERIMENT_COMPLETE=FAIL', flush=True)
        print('SESSION_ISSUES=' + repr(issues), flush=True)
        return 1
    try:
        verify_saved(directory)
        evidence_bytes = sum(path.stat().st_size for path in directory.rglob('*')
                             if path.is_file())
        with REPORT.open('x', encoding='utf-8') as handle:
            handle.write(report(records, deploy_s, cleanup_s, directory, evidence_bytes))
    except (OSError, ValueError, RuntimeError, AssertionError) as exc:
        print(f'FINAL_VERIFICATION_ERROR={exc}', file=sys.stderr)
        return 1
    print(f'SESSION_EVIDENCE_BYTES={evidence_bytes}')
    print(f'TOPOLOGY_DEPLOYMENT_SECONDS={deploy_s:.5f}')
    print(f'TOPOLOGY_CLEANUP_SECONDS={cleanup_s:.5f}')
    print('V07_FINAL_CLEANUP=PASS')
    print('REPORT_PATH=' + str(REPORT.relative_to(PROJECT)))
    print('V07_EXPERIMENT_COMPLETE=PASS')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--check', action='store_true', help='Read-only local validation (default)')
    action.add_argument('--execute', action='store_true', help='Perform real WSL network experiment')
    action.add_argument('--verify', type=Path, help='Verify completed session offline')
    args = parser.parse_args()
    try:
        if args.verify is not None:
            verify_saved(args.verify.resolve())
            return 0
        plan = local_check()
        if not args.execute:
            print('V07_PREFLIGHT_SOURCE_REVIEW=PASS')
            return 0
        return execute(plan)
    except (OSError, ValueError, KeyError, RuntimeError, AssertionError) as exc:
        print(f'V07_PREFLIGHT_ERROR={exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
