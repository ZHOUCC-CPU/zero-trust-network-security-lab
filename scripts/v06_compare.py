#!/usr/bin/env python3
"""V0.6 fixed-matrix baseline-versus-segmented experiment.

Run as ordinary user. --check is read-only; --execute explicitly deploys and
removes the owned namespace lab through *reviewed root-owned scripts*.
It never executes a script from a Windows/DrvFS path with root privileges.
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
import subprocess
import sys

MATRIX = Path('tests/v06_scenario_matrix.json')
BASELINE_SOURCE = Path('scripts/test_v06_baseline.sh')
ROOT_DIR = '/root/ztlab-v03-reviewed'
ROOT_BASELINE = ROOT_DIR + '/test_v06_baseline.sh'
ROOT_TOPOLOGY_UP = ROOT_DIR + '/topology_up.sh'
ROOT_TOPOLOGY_CHECK = ROOT_DIR + '/check_topology.sh'
ROOT_POLICY = ROOT_DIR + '/load_v04_policy.sh'
ROOT_V04_TEST = ROOT_DIR + '/test_v04_firewall.sh'
ROOT_TOPOLOGY_DOWN = ROOT_DIR + '/topology_down.sh'
STATE = '/var/lib/ztlab-v03/state'
REPORT = Path('reports/V0.6_EXPERIMENT_REPORT.md')
EVIDENCE_BASE = Path('evidence/v06_runs')
ROUNDS = 3
EXPECTED = {
    'employee_to_app_tcp8080': ('employee-ns', '10.200.20.2', 'tcp', 8080, 'ALLOW', 'ZT_LAB_V04_HTTP_OK'),
    'app_to_data_tcp5432': ('app-ns', '10.200.30.2', 'tcp', 5432, 'ALLOW', 'ZT_LAB_V04_TCP5432_OK'),
    'employee_to_data_icmp': ('employee-ns', '10.200.30.2', 'icmp', None, 'DENY', None),
    'employee_to_data_tcp5432': ('employee-ns', '10.200.30.2', 'tcp', 5432, 'DENY', 'ZT_LAB_V04_TCP5432_OK'),
    'employee_to_app_tcp8081': ('employee-ns', '10.200.20.2', 'tcp', 8081, 'DENY', 'ZT_LAB_V04_PORT8081'),
    'data_to_app_tcp8080': ('data-ns', '10.200.20.2', 'tcp', 8080, 'DENY', 'ZT_LAB_V04_HTTP_OK'),
}


def stamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_once(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='') as fh:
        fh.write(content)


def command(args: list[str], deadline: int = 150) -> tuple[int, str]:
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, errors='replace', check=False, timeout=deadline)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b''
        if isinstance(output, bytes):
            output = output.decode('utf-8', errors='replace')
        return 124, output + '\nERROR: outer subprocess timeout\n'
    except OSError as exc:
        return 127, f'ERROR: command could not run: {exc}\n'


def required(args: list[str], label: str, deadline: int = 150) -> str:
    code, output = command(args, deadline)
    if code != 0:
        raise RuntimeError(f'{label} exited {code}: {output[-2500:]}')
    return output


def validate_source() -> list[dict]:
    if MATRIX.is_symlink() or BASELINE_SOURCE.is_symlink():
        raise ValueError('Matrix or baseline script is a symlink.')
    matrix = json.loads(MATRIX.read_text(encoding='utf-8'))
    data = matrix['scenarios']
    if matrix['schema_version'] != '1.0' or len(data) != len(EXPECTED):
        raise ValueError('Unexpected scenario matrix schema/count.')
    if {s['id'] for s in data} != set(EXPECTED):
        raise ValueError('Scenario IDs differ from expected fixed set.')
    for s in data:
        src, address, protocol, port, segmented, body = EXPECTED[s['id']]
        for key, expected_value in (
            ('source_namespace', src), ('destination_ip', address),
            ('protocol', protocol), ('destination_port', port),
            ('baseline_expected', 'ALLOW'), ('segmented_expected', segmented),
            ('expected_http_body', body),
        ):
            if s[key] != expected_value:
                raise ValueError(f'Matrix mismatch: {s["id"]}.{key}')

    script = BASELINE_SOURCE.read_text(encoding='utf-8')
    # Bash line continuations and ordinary extra spaces must not cause false negatives.
    normalized = re.sub(r'\\\r?\n[ \t]*', ' ', script)
    normalized = re.sub(r'[ \t]+', ' ', normalized)
    calls = re.findall(
        r'(?m)^run_http ([a-z0-9_]+) ([a-z0-9-]+) '
        r'(\d+(?:\.\d+){3}) (\d+) ([A-Z0-9_]+)[ \t]*$', normalized,
    )
    http_cases = [s for s in data if s['protocol'] == 'tcp']
    if len(calls) != 5 or len({a[0] for a in calls}) != 5:
        raise ValueError(f'Expected five unique HTTP calls, found {len(calls)}.')
    observed = {name: (src, dst, int(port), body)
                for name, src, dst, port, body in calls}
    for s in http_cases:
        expected_call = (s['source_namespace'], s['destination_ip'],
                         s['destination_port'], s['expected_http_body'])
        if observed.get(s['id']) != expected_call:
            raise ValueError(f'HTTP call mismatch: {s["id"]}')
    if set(observed) != {s['id'] for s in http_cases}:
        raise ValueError('Unexpected HTTP scenario.')
    ping_match = re.search(r'(?ms)^run_ping\(\)\s*\{(.*?)^\}', script)
    if not ping_match or len(re.findall(r'(?m)^run_ping\s*$', script)) != 1:
        raise ValueError('Missing or repeated ICMP probe.')
    ping_body = re.sub(r'\\\r?\n\s*', ' ', ping_match.group(1))
    if not re.search(r'ip\s+netns\s+exec\s+employee-ns\s+ping\s+-n\s+-c\s+2'
                     r'\s+-W\s+1\s+10\.200\.30\.2\b', ping_body):
        raise ValueError('ICMP probe address or arguments mismatch.')
    for marker in ('flock -n 9', 'NS_${ns//-/_}_INODE',
                   'BASELINE_RESULT=PASS', 'nft list tables',
                   'trap cleanup EXIT'):
        if marker not in script:
            raise ValueError(f'Baseline runner preflight marker missing: {marker}')
    required(['bash', '-n', str(BASELINE_SOURCE)], 'Baseline Bash syntax', 10)
    print('MATRIX_CONSISTENCY=PASS')
    print('HTTP_SCENARIOS=5/5')
    print('ICMP_SCENARIOS=1/1')
    print('BASH_SYNTAX=PASS')
    return data


def parse_round(text: str, phase: str, matrix: list[dict]) -> tuple[list[dict], list[str]]:
    issues: list[str] = []
    ids = {x['id'] for x in matrix}
    results = re.findall(r'(?m)^(PASS|FAIL)\|([a-z0-9_]+)\|([^\r\n]*)$', text)
    test_results = [(v, ident, detail) for v, ident, detail in results if ident in ids]
    if len(test_results) != 6 or {ident for _, ident, _ in test_results} != ids:
        issues.append('Six distinct scenarios were not recorded.')
    if any(v != 'PASS' for v, _, _ in test_results):
        issues.append('One or more scenario verdicts were FAIL.')
    if len(re.findall(r'(?m)^PASS\|preflight\|three isolated test servers are listening$', text)) != 1:
        issues.append('Test server preflight PASS missing.')
    for field, expected in (('SUMMARY|passed', '6'), ('SUMMARY|failed', '0')):
        if len(re.findall(rf'(?m)^{re.escape(field)}\|{expected}$', text)) != 1:
            issues.append(f'{field} missing or incorrect.')
    result_key = 'BASELINE_RESULT' if phase == 'baseline' else 'REGRESSION_RESULT'
    if len(re.findall(rf'(?m)^{result_key}=PASS$', text)) != 1:
        issues.append(f'{result_key}=PASS missing.')
    if len(re.findall(r'(?m)^RUNNER_EXIT_CODE=0$', text)) != 1:
        issues.append('Runner exit code was not zero.')
    if len(re.findall(r'(?m)^RUNNER_EXIT_CODE=', text)) != 1:
        issues.append('Ambiguous exit code fields.')
    # V0.4 runner explicitly checks allow/drop counters for each case.
    # Baseline runner checks HTTP response bodies and ICMP replies.
    if phase == 'segmented':
        for verdict, ident, detail in test_results:
            if verdict == 'PASS' and not re.search(r'counter \+[1-9][0-9]*', detail):
                issues.append(f'No increasing firewall counter shown for {ident}.')
    return ([{'scenario': ident, 'verdict': verdict, 'detail': detail}
             for verdict, ident, detail in test_results], issues)


def preflight_root() -> None:
    if os.geteuid() == 0:
        raise RuntimeError('Run orchestrator as normal WSL user, not root.')
    required(['sudo', '-n', 'true'], 'Cached sudo authentication', 10)
    directory_permission = required(['sudo', '-n', 'stat', '-c', '%u:%a', ROOT_DIR], 'Root stage directory')
    if directory_permission.strip() != '0:700':
        raise RuntimeError('Unexpected root reviewed directory owner/mode.')
    for root_script in (ROOT_TOPOLOGY_UP, ROOT_TOPOLOGY_CHECK, ROOT_POLICY,
                        ROOT_V04_TEST, ROOT_TOPOLOGY_DOWN):
        owner_perm = required(['sudo', '-n', 'stat', '-c', '%u:%a', root_script],
                              f'Reviewed script metadata {root_script}', 10).strip()
        if owner_perm != '0:700':
            raise RuntimeError(f'Unexpected root script owner/mode: {root_script}: {owner_perm}')
    if required(['sudo', '-n', 'ip', 'netns', 'list'], 'Preflight namespaces').strip():
        raise RuntimeError('Pre-existing network namespaces detected; refusing deployment.')
    rc, _ = command(['sudo', '-n', 'test', '-e', STATE], 10)
    if rc == 0:
        raise RuntimeError('Active or stale project state file exists; refusing deployment.')
    if rc != 1:
        raise RuntimeError('Could not safely check state file.')
    rc, _ = command(['sudo', '-n', 'test', '-e', ROOT_BASELINE], 10)
    if rc == 0:
        raise RuntimeError('Root-staged V0.6 script already exists; review manually first.')
    if rc != 1:
        raise RuntimeError('Could not safely check staged script.')


def stage_baseline() -> None:
    required(['sudo', '-n', 'install', '-o', 'root', '-g', 'root', '-m', '700',
              '--', str(BASELINE_SOURCE), ROOT_BASELINE], 'Stage root-owned baseline script', 15)
    permission = required(['sudo', '-n', 'stat', '-c', '%u:%a', ROOT_BASELINE], 'Staged script mode')
    if permission.strip() != '0:700':
        raise RuntimeError('Root staged script has unexpected ownership or mode.')
    output = required(['sudo', '-n', 'sha256sum', ROOT_BASELINE], 'Staged script SHA-256')
    staged_digest = output.split()[0]
    source_digest = sha(BASELINE_SOURCE.read_bytes())
    if staged_digest != source_digest:
        raise RuntimeError('Staged script differs from local reviewed source.')
    print('ROOT_STAGING_SHA256_MATCH=PASS', flush=True)


def capture_once(log: Path, command_args: list[str], label: str, deadline: int = 150) -> tuple[int, str]:
    start = now()
    rc, output = command(command_args, deadline)
    end = now()
    body = (f'=== {label} ===\nSTARTED_UTC={start}\n{output.rstrip()}\n'
            f'RUNNER_EXIT_CODE={rc}\nFINISHED_UTC={end}\n')
    save_once(log, body)
    return rc, body


def snapshot(path: Path, cmd: list[str], name: str) -> str:
    output = required(cmd, name, 60)
    save_once(path, output)
    return output


def verify_cleanup() -> None:
    if required(['sudo', '-n', 'ip', 'netns', 'list'], 'Final namespace check').strip():
        raise RuntimeError('Network namespaces remain after teardown.')
    rc, _ = command(['sudo', '-n', 'test', '-e', STATE], 10)
    if rc != 1:
        raise RuntimeError('Active state file remains, or state check failed.')
    for iface in ('gw-emp', 'gw-app', 'gw-data', 'emp-gw', 'app-gw', 'data-gw'):
        rc, _ = command(['ip', 'link', 'show', 'dev', iface], 10)
        if rc == 0:
            raise RuntimeError(f'Project interface still exists: {iface}')
    print('FINAL_CLEANUP_VERIFIED=PASS', flush=True)


def write_data(directory: Path, matrix: list[dict], records: list[dict],
               rows: list[dict], cleanup_ok: bool, issues: list[str]) -> None:
    summary = {
        'schema_version': '1.0',
        'project_version': 'V0.6',
        'type': 'baseline_versus_segmented_repeated_experiment',
        'rounds_per_condition_requested': ROUNDS,
        'rounds_attempted': {name: sum(r['condition'] == name for r in records)
                             for name in ('baseline', 'segmented')},
        'rounds_passed': {name: sum(r['condition'] == name and r['valid'] for r in records)
                          for name in ('baseline', 'segmented')},
        'scenario_executions_verified': len(rows),
        'cleanup_verified': cleanup_ok,
        'all_passed': not issues and cleanup_ok and len(rows) == 36,
        'issues': issues,
        'rounds': records,
        'note': 'Six defined scenarios repeated three times per condition; this is not 36 distinct attacks.',
    }
    save_once(directory / 'summary.json', json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    fields = ['condition', 'round', 'scenario', 'expected_policy', 'observed_behavior',
              'verdict', 'detail', 'log_file', 'log_sha256']
    csv_path = directory / 'scenarios.csv'
    fd = os.open(csv_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)
    print(f'SESSION_DIR={directory}')
    print(f'ROUNDS_BASELINE_PASSED={summary["rounds_passed"]["baseline"]}/{ROUNDS}')
    print(f'ROUNDS_SEGMENTED_PASSED={summary["rounds_passed"]["segmented"]}/{ROUNDS}')
    print(f'SCENARIO_EXECUTIONS_VERIFIED={len(rows)}/36')
    print(f'FINAL_RESULT={"PASS" if summary["all_passed"] else "FAIL"}')


def make_report(directory: Path, matrix: list[dict]) -> None:
    summary = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    if not summary['all_passed']:
        raise RuntimeError('Cannot generate PASS report from incomplete/failed run.')
    with (directory / 'scenarios.csv').open(encoding='utf-8', newline='') as fh:
        rows = list(csv.DictReader(fh))
    if len(rows) != 36:
        raise ValueError("Invalid scenario row count")
    comparison = []
    for s in matrix:
        phase_rows = {p: [r for r in rows if r['scenario'] == s['id'] and r['condition'] == p]
                      for p in ('baseline', 'segmented')}
        if not all(len(pr) == 3 and all(r['verdict'] == 'PASS' for r in pr)
                   for pr in phase_rows.values()):
            raise ValueError('Invalid scenario groups/verdicts')
        comparison.append(f'| `{s["id"]}` | {s["baseline_expected"]} | '
                          f'{s["segmented_expected"]} | 3/3 | 3/3 |')
    stamp_date = datetime.now(timezone.utc).strftime('%Y-%m-%d UTC')
    report_text = f'''# V0.6 Experiment Report
## Controlled Baseline-versus-Segmented Comparison

- **Project:** Zero Trust Network Security Lab
- **Version:** V0.6
- **Report generated:** {stamp_date}
**Result:** PASS (3 baseline rounds + 3 segmented rounds; 36/36 scenario executions)

## Objective

Compare the same six communication scenarios under a permissive lab-routing baseline and the V0.4 nftables default-drop segmentation policy.
The documented segmented policy permits Employee -> Application TCP 8080 and Application -> Data TCP 5432, while denying the four remaining scenarios.

## Test controls

- Four WSL2 Ubuntu Linux network namespaces: employee-ns, app-ns, data-ns, zt-gw-ns.
- Same /30 IP topology and destinations for both conditions.
- Three temporary Python HTTP listeners on App TCP 8080, App TCP 8081 and Data TCP 5432.
- The TCP 5432 listener is **not PostgreSQL**; its service response is a controlled test fixture.
- Baseline condition: new topology, no nftables table in the gateway namespace; six scenarios expected to connect.
- Segmented condition: same live topology with V0.4 default-drop nftables policy loaded; two allowed, four denied.
- Three repeat rounds in each condition, sequentially (not randomized). Each runner used bounded execution and independently generated per-round logs.

## Scenario comparison

| Scenario | Baseline target | Segmented target | Baseline passed | Segmented passed |
|---|---|---|---|---|
{chr(10).join(comparison)}

All 36 scenario executions matched their **condition-specific** expectations.

## Security interpretation

- Baseline: four flows not authorized by the target segmented policy were reachable in each round (**12 exposure observations** across three repeats). They are expected outcomes for the deliberately permissive control, not implementation failures.
- Segmented: the same four flows were blocked in each round (**12/12 expected denials**), with observed failure plus increasing drop counters in the gateway.
- The two approved flows were successful in all segmented rounds (**6/6 expected allows**), with increasing allow counters.
- **Observed false allows: 0/12; observed false denies: 0/6** within the defined segmented test matrix. Operational failures: 0 in the completed rounds.
- These counts are conditional on this narrow test matrix. They are not statistical estimates of a real deployment's error rates.

## Evidence and verification

Run directory: `{directory}`

- `baseline_round_01.txt` through `baseline_round_03.txt`
- `segmented_round_01.txt` through `segmented_round_03.txt`
- `summary.json` and `scenarios.csv`
- `baseline_nft_tables.txt`, `segmented_nft_rules.txt`, `topology_validation.txt`
- `cleanup.txt`

SHA-256 digests for each six-round log are recorded in `summary.json`. The offline verifier re-reads original logs, recomputes hashes and checks exact scenario/CSV agreement. These are local consistency checks, not independently authenticated tamper-proof signatures.

## Safe completion

The project-owned namespaces and their policy were removed using the reviewed topology cleanup script. A residual namespace, state-file and known-interface check was required for a PASS result. The root-owned staged test script remains installed for audit/reuse, outside the Windows-writable project tree.

## Limitations

- Single WSL2 environment and fixed traffic topology; no production identity, user authentication, device attestation, lateral-movement detection or continuous authorization.
- No randomized order, concurrent workload, throughput measurement, latency benchmark or separate host-load measurement; those are outside V0.6.
- The V0.4 deny validator checks timeout plus drop counters. It does not evaluate every network failure mode.
- The original baseline test script uses hard-coded inputs that were cross-checked against the fixed JSON matrix before execution.
- The compared conditions are sequential, so time-related environmental changes are not eliminated.

## Conclusion

In this isolated laboratory, enabling the documented microsegmentation policy blocked all twelve test instances of the four disallowed flow types while preserving all six allowed test instances across three repetitions. The experiments support the policy's effectiveness within these specific conditions, not full Zero Trust compliance.

## Next milestone

V0.7: CPU, memory, throughput, latency, deployment/teardown cost and uncertainty assessment.
'''
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    save_once(REPORT, report_text)
    print(f'REPORT_PATH={REPORT}')


def execute(matrix: list[dict]) -> int:
    print('=== V0.6 LIVE COMPARATIVE EXPERIMENT ===', flush=True)
    if REPORT.exists():
        print(f'ERROR: Report already exists: {REPORT}; refusing overwrite.', file=sys.stderr)
        return 2
    try:
        preflight_root()
        stage_baseline()
    except (RuntimeError, ValueError) as exc:
        print(f'PREFLIGHT_ERROR={exc}', file=sys.stderr)
        return 2

    EVIDENCE_BASE.mkdir(parents=True, exist_ok=True)
    directory = EVIDENCE_BASE / f'run_{stamp()}_{os.getpid()}'
    directory.mkdir(mode=0o700)
    print(f'SESSION_DIR={directory}', flush=True)
    records: list[dict] = []
    rows: list[dict] = []
    issues: list[str] = []
    topology_deployed = False
    cleanup_ok = False
    by_id = {s['id']: s for s in matrix}

    try:
        print('DEPLOYING_TOPOLOGY=START', flush=True)
        snapshot(directory / 'topology_deployment.txt',
                 ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=10s', '60s',
                  'bash', ROOT_TOPOLOGY_UP], 'Topology deployment')
        topology_deployed = True
        check = snapshot(directory / 'topology_validation.txt',
                         ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=10s', '60s',
                          'bash', ROOT_TOPOLOGY_CHECK], 'Topology validation')
        if 'SUMMARY|topology_failures|0' not in check:
            raise RuntimeError('Topology validation did not report zero failures.')
        baseline_tables = snapshot(directory / 'baseline_nft_tables.txt',
                                   ['sudo', '-n', 'ip', 'netns', 'exec', 'zt-gw-ns',
                                    'nft', 'list', 'tables'], 'Baseline nftables inventory')
        if baseline_tables.strip():
            raise RuntimeError('Baseline gateway contains nftables tables; experiment refused.')
        print('BASELINE_FIREWALL_TABLES=NONE', flush=True)

        for phase in ('baseline', 'segmented'):
            if phase == 'segmented':
                snapshot(directory / 'policy_load.txt',
                         ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=10s', '45s',
                          'bash', ROOT_POLICY], 'V0.4 policy loading')
                rules = snapshot(directory / 'segmented_nft_rules.txt',
                                 ['sudo', '-n', 'ip', 'netns', 'exec', 'zt-gw-ns', 'nft', '-a',
                                  'list', 'table', 'inet', 'ztlab_v04'], 'V0.4 active rules')
                for marker in ('policy drop;', 'ct state established,related',
                               'iifname "gw-emp" oifname "gw-app"',
                               'iifname "gw-app" oifname "gw-data"', 'counter packets'):
                    if marker not in rules:
                        raise RuntimeError(f'Missing active firewall requirement: {marker}')
                print('SEGMENTATION_POLICY_VERIFIED=PASS', flush=True)

            root_runner = ROOT_BASELINE if phase == 'baseline' else ROOT_V04_TEST
            for round_index in range(1, ROUNDS + 1):
                print(f'ROUND_START={phase}:{round_index}/{ROUNDS}', flush=True)
                log = directory / f'{phase}_round_{round_index:02d}.txt'
                rc, content = capture_once(
                    log, ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=10s',
                          '120s', 'bash', root_runner],
                    f'V0.6 {phase.upper()} ROUND {round_index:02d}')
                parsed, problems = parse_round(content, phase, matrix)
                if rc != 0:
                    problems.append(f'Runner exit status {rc}')
                valid = not problems
                digest = sha(log.read_bytes())
                records.append({'condition': phase, 'round': round_index,
                                'log_file': str(log), 'log_sha256': digest,
                                'runner_exit_code': rc, 'valid': valid, 'issues': problems})
                if not valid:
                    raise RuntimeError(f'{phase} round {round_index} failed: {problems}')
                for item in parsed:
                    scenario = by_id[item['scenario']]
                    expected = scenario['baseline_expected'] if phase == 'baseline' else scenario['segmented_expected']
                    rows.append({'condition': phase, 'round': round_index,
                                 'scenario': item['scenario'], 'expected_policy': expected,
                                 'observed_behavior': expected, 'verdict': item['verdict'],
                                 'detail': item['detail'], 'log_file': str(log),
                                 'log_sha256': digest})
                print(f'ROUND_{phase.upper()}_{round_index:02d}=PASS (6/6)', flush=True)
    except (RuntimeError, ValueError, KeyboardInterrupt) as exc:
        issues.append(str(exc))
        print(f'EXPERIMENT_ERROR={exc}', file=sys.stderr, flush=True)
    finally:
        if topology_deployed:
            code, output = capture_once(
                directory / 'cleanup.txt',
                ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=10s', '90s',
                 'bash', ROOT_TOPOLOGY_DOWN], 'V0.6 OWNED TOPOLOGY CLEANUP', 110)
            if code == 0:
                try:
                    verify_cleanup()
                    cleanup_ok = True
                except RuntimeError as exc:
                    issues.append(f'Cleanup verification: {exc}')
            else:
                issues.append(f'Cleanup runner failed ({code}): {output[-1000:]}')
        else:
            issues.append('Topology was not confirmed deployed; no automatic teardown attempted.')

    write_data(directory, matrix, records, rows, cleanup_ok, issues)
    if issues:
        print('ERRORS=' + ' ; '.join(issues), file=sys.stderr)
        return 1
    try:
        verify_saved(directory, matrix)
        make_report(directory, matrix)
    except (RuntimeError, ValueError, AssertionError, OSError) as exc:
        print(f'FINAL_VERIFICATION_ERROR={exc}', file=sys.stderr)
        return 1
    print('V06_EXPERIMENT_COMPLETE=PASS')
    return 0


def verify_saved(directory: Path, matrix: list[dict]) -> None:
    summary = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    if not summary['all_passed'] or not summary['cleanup_verified']:
        raise ValueError('Experiment/cleanup did not pass.')
    records = summary['rounds']
    if len(records) != 6:
        raise ValueError('Expected exactly six round records.')
    with (directory / 'scenarios.csv').open(encoding='utf-8', newline='') as fh:
        csv_rows = list(csv.DictReader(fh))
    if len(csv_rows) != 36:
        raise ValueError('Expected exactly 36 scenario rows.')
    for phase in ('baseline', 'segmented'):
        for i in range(1, ROUNDS + 1):
            matches = [r for r in records if r['condition'] == phase and r['round'] == i]
            if len(matches) != 1 or not matches[0]['valid']:
                raise ValueError(f'Invalid/missing record: {phase} {i}')
            record = matches[0]
            log = directory / f'{phase}_round_{i:02d}.txt'
            if Path(record['log_file']) != log:
                raise ValueError(f'Log file path mismatch: {phase} {i}')
            raw = log.read_bytes()
            if sha(raw) != record['log_sha256']:
                raise ValueError(f'Log SHA256 mismatch: {phase} {i}')
            results, issues = parse_round(raw.decode('utf-8'), phase, matrix)
            if issues:
                raise ValueError(f'Round parse failure {phase} {i}: {issues}')
            group = [r for r in csv_rows if r['condition'] == phase and r['round'] == str(i)]
            if len(group) != 6 or {r['scenario'] for r in group} != set(EXPECTED):
                raise ValueError(f'CSV group mismatch: {phase} {i}')
            original = {x['scenario']: x for x in results}
            for r in group:
                scenario = next(x for x in matrix if x['id'] == r['scenario'])
                target = scenario['baseline_expected'] if phase == 'baseline' else scenario['segmented_expected']
                if not (r['log_sha256'] == record['log_sha256'] and
                        r['log_file'] == str(log) and r['verdict'] == 'PASS' and
                        r['detail'] == original[r['scenario']]['detail'] and
                        r['expected_policy'] == target and r['observed_behavior'] == target):
                    raise ValueError(f'CSV/log mismatch: {phase} {i} {r["scenario"]}')
    print('INDEPENDENT_LOG_HASH_AND_CSV_VALIDATION=PASS', flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--check', action='store_true', help='Validate local script/matrix only (read-only).')
    choice.add_argument('--execute', action='store_true', help='Explicitly run 3+3 live rounds and owned cleanup.')
    choice.add_argument('--verify', type=Path, metavar='RUN_DIR', help='Offline verify saved run evidence.')
    args = parser.parse_args()
    try:
        matrix = validate_source() if not args.verify else json.loads(MATRIX.read_text(encoding='utf-8'))['scenarios']
        if args.check:
            print('V06_PREFLIGHT_SOURCE_REVIEW=PASS')
            return 0
        if args.verify:
            verify_saved(args.verify, matrix)
            print('V06_OFFLINE_VERIFICATION=PASS')
            return 0
        return execute(matrix)
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        print(f'ERROR={exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
