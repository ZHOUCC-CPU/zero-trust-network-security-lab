#!/usr/bin/env python3
"""V0.8 controlled completion: 18 live segmented audit cases + evidence + report.

Run as ordinary WSL user from the project's top directory.
  --check            Offline source/plan review, no root calls or packets.
  --execute          Deploy audited namespaces, 18 probes, guarded cleanup,
                     validate evidence and create report; no Git commit.
  --execute --commit Same, and commit only verified V0.8 paths locally to main.

On failure, leaves incomplete evidence untouched and refuses a PASS or commit.
No external network, Windows firewall changes, persistent daemons or host logs.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

# Hashes proven by earlier V0.8 step outputs. Never execute changed scripts as root.
FILES = {
    'tests/v08_audit_plan.json': 'd6602322a0e7f0f0533e8e5094112e19579d7565f5637db5c522d51cef5313d9',
    'docs/V0.8_AUDIT_DESIGN.md': '346b8cfd80a9b5d8345ec897f65bab0819bae0dd00ad58f080b735b92dd3d202',
    'scripts/v08_counter_parser.py': 'c6190dc53a884e28415c7c35fcd5d938dcfdce180c5c262245dd9135b2d46ec0',
    'scripts/v08_counter_delta.py': '8004f5e9008cf8a6b1fc3db45eb443dc7b8010fdb20cd33967c821015e573547',
    'scripts/v08_evidence_validator.py': '1675b6cb65a13cfbb30ff7b54ea3b9676a42b88794120f0e868b5581ad8e71d0',
    'scripts/v08_live_snapshot.py': 'a66a600de5f8d3821000362637e3c4f04f4f53e117b9ecc5c452c19f6ed2c62b',
    'scripts/v08_root_audit_case.py': '32db4f1dbc52044cecb01298601f6fb34181c4cc045bddf0b560631aaec2db74',
}
ROOT_DIR = '/root/ztlab-v03-reviewed'
ROOT_CASE = ROOT_DIR + '/v08_root_audit_case.py'
ROOT_UP = ROOT_DIR + '/topology_up.sh'
ROOT_DOWN = ROOT_DIR + '/topology_down.sh'
ROOT_POLICY = ROOT_DIR + '/load_v04_policy.sh'
STATE = '/var/lib/ztlab-v03/state'
EVIDENCE_BASE = Path('evidence/v08_runs')
REPORT = Path('reports/V0.8_EXPERIMENT_REPORT.md')
EXPECTED = {
    'employee_to_app_tcp8080': ('ALLOW','allow_emp_app'),
    'app_to_data_tcp5432': ('ALLOW','allow_app_data'),
    'employee_to_data_icmp': ('DENY','drop'),
    'employee_to_data_tcp5432': ('DENY','drop'),
    'employee_to_app_tcp8081': ('DENY','drop'),
    'data_to_app_tcp8080': ('DENY','drop'),
}

class ReleaseError(RuntimeError):
    pass

def require(ok, message):
    if not ok:
        raise ReleaseError(message)

def command(argv, timeout=30):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              check=False, errors='replace')
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError(f'command interrupted: {argv[:3]} ({type(exc).__name__})') from exc

def run_checked(argv, label, timeout=30):
    result = command(argv, timeout)
    require(result.returncode == 0,
            f'{label} exit={result.returncode}: {result.stdout[-500:]} {result.stderr[-800:]}')
    return result.stdout

def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def save(path, data):
    with path.open('x', encoding='utf-8', newline='') as stream:
        stream.write(data)

def json_save(path, data):
    save(path, json.dumps(data, indent=2, ensure_ascii=False) + '\n')

def utcstamp():
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')

def iso_utc():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def validate_sources():
    require(os.geteuid() != 0, 'run this orchestrator as ordinary WSL user')
    require(Path('.git').exists() and not Path('.git').is_symlink(), 'run from project root')
    for name, digest in FILES.items():
        path = Path(name)
        require(path.is_file() and not path.is_symlink(), f'missing/symlinked source: {name}')
        require(file_hash(path) == digest, f'source SHA-256 mismatch: {name}')
        if name.endswith('.py'):
            compile(path.read_text(encoding='utf-8'), name, 'exec')
    require(run_checked(['git','rev-parse','--short','HEAD'],'git HEAD').strip() == '97f3ef3',
            'unexpected Git commit')
    require(run_checked(['git','branch','--show-current'],'branch').strip() == 'main',
            'unexpected branch')
    require(command(['git','diff','--quiet']).returncode == 0, 'tracked files modified')
    require(command(['git','diff','--cached','--quiet']).returncode == 0, 'index already staged')
    plan = json.loads(Path('tests/v08_audit_plan.json').read_text(encoding='utf-8'))
    require(plan.get('schema_version') == '1.0' and plan.get('rounds') == 3,
            'unexpected plan schema/rounds')
    scenarios = plan.get('scenarios')
    require(isinstance(scenarios, list) and len(scenarios) == 6,
            'unexpected plan scenarios')
    mapping = {}
    for scenario in scenarios:
        name = scenario['id']
        require(name not in mapping and EXPECTED.get(name) == (
            scenario['expected_verdict'], scenario['expected_counter']),
            f'unexpected scenario: {name}')
        mapping[name] = (scenario['expected_verdict'],scenario['expected_counter'])
    require(mapping == EXPECTED,'incomplete scenario set')
    require(plan.get('safety', {}).get('isolated_namespaces_only') is True and
            plan.get('safety', {}).get('modify_host_firewall') is False and
            plan.get('safety', {}).get('external_traffic') is False,
            'unsafe audit plan')
    root_check = run_checked([sys.executable, '-B', 'scripts/v08_root_audit_case.py','--check'],
                             'root-case offline source check')
    require('V08_ROOT_CASE_SOURCE_CHECK=PASS' in root_check,
            'missing root-case offline source indicator')
    evidence_check = run_checked([sys.executable, '-B', 'scripts/v08_evidence_validator.py',
                                  '--check-plan', 'tests/v08_audit_plan.json'],
                                 'validator plan check')
    require('V08_EVIDENCE_PLAN_CHECK=PASS' in evidence_check,
            'validator plan check not reported')
    print('V08_SOURCE_HASH_AND_SYNTAX=PASS', flush=True)
    print('V08_PLAN_AND_VALIDATOR=PASS', flush=True)
    print('PLANNED_LIVE_CASES=18', flush=True)
    return plan

def sudo(args, label, timeout=30):
    return run_checked(['sudo', '-n'] + args, label, timeout)

def sudo_test(flag, path):
    result = command(['sudo','-n','test',flag,path], 8)
    require(result.returncode in (0,1), f'sudo test failed for {path}')
    return result.returncode == 0

def root_preflight():
    sudo(['true'],'cached sudo',10)
    require(sudo(['stat','-c','%u:%g:%a',ROOT_DIR], 'root dir').strip()=='0:0:700',
            'unsafe root stage directory')
    for source_name in ('topology_up.sh', 'load_v04_policy.sh'):
        root_path = ROOT_DIR + '/' + source_name
        require(sudo(['stat','-c','%u:%g:%a',root_path],'root script mode').strip()=='0:0:700',
                f'unsafe root executable: {root_path}')
        subprocess_result=command(['sudo','-n','cmp','-s', 'scripts/'+source_name, root_path])
        require(subprocess_result.returncode == 0, f'root source mismatch: {source_name}')
    require(sudo(['stat','-c','%u:%g:%a',ROOT_DOWN],'down mode').strip()=='0:0:700',
            'unsafe cleanup script')
    require(sudo(['sha256sum',ROOT_DOWN],'cleanup source').split()[0] ==
            '8a71b3bf81bd9267f95ef264c1593ce8ae15ac74811f576d02819d4ddf301080',
            'unexpected cleanup script')
    require(sudo(['ip','netns','list'],'namespace check').strip() == '',
            'unexpected preexisting namespace')
    require(not sudo_test('-e',STATE) and not sudo_test('-L',STATE),
            'stale deployment state')
    require(not REPORT.exists() and not REPORT.is_symlink(),
            'V0.8 report already exists; refusing overwrite')
    exists = sudo_test('-e',ROOT_CASE) or sudo_test('-L',ROOT_CASE)
    if exists:
        require(sudo(['stat','-c','%u:%g:%a', ROOT_CASE], 'staged script').strip()=='0:0:700',
                'unsafe existing root runner')
        require(sudo(['sha256sum', ROOT_CASE], 'root runner hash').split()[0]==
                FILES['scripts/v08_root_audit_case.py'],
                'existing root runner differs')
    else:
        # No root execution from user-writable project paths. Stage root-owned,
        # verify the installed bytes and permissions, and execute only staged copy.
        sudo(['install','-o','root','-g','root','-m','700','--',
              str(Path('scripts/v08_root_audit_case.py').resolve()),ROOT_CASE],
             'reviewed root staging')
        require(sudo(['stat','-c','%u:%g:%a',ROOT_CASE],'installed stage mode').strip()==
                '0:0:700', 'unsafe staged mode')
        require(sudo(['sha256sum',ROOT_CASE],'installed stage hash').split()[0]==
                FILES['scripts/v08_root_audit_case.py'], 'staged hash mismatch')
    print('V08_ROOT_STAGE_AND_PREDEPLOY=PASS',flush=True)

def clean_state():
    try:
        names = sudo(['ip','netns','list'],'postclean namespace check',15).strip()
        marker = sudo_test('-e',STATE) or sudo_test('-L',STATE)
        return names == '' and not marker
    except ReleaseError:
        return False

def create_report(session, records):
    allowed = [r for r in records if r['expected_verdict'] == 'ALLOW']
    denied = [r for r in records if r['expected_verdict'] == 'DENY']
    per_scenario = []
    for case_id in EXPECTED:
        group = [r for r in records if r['scenario_id'] == case_id]
        values = [r['packet_delta'] for r in group]
        per_scenario.append((case_id,EXPECTED[case_id][0], '/'.join(str(v) for v in values)))
    rows = '\n'.join(f'| `{name}` | {verdict} | {deltas} | 3/3 |'
                     for name,verdict,deltas in per_scenario)
    report = f'''# V0.8 — Security Audit and Reproducibility Review

**Project:** Zero Trust Network Security Lab  
**Generated (UTC):** {iso_utc()}  
**Outcome:** PASS — 18/18 bounded, live isolated-network audit cases; guarded cleanup verified.

## Methodology

- Four Linux network namespaces; gateway nftables `inet ztlab_v04` forward policy.
- Only the segmented condition tested. Three ordered repetitions of six scenarios.
- Per-scenario nftables JSON snapshots captured immediately before/after a bounded test.
- HTTP 200 plus expected response body for ALLOW; TCP connect timeout or ICMP echo
  packet loss for DENY, with a separately verified positive intended rule counter delta.
- All tests executed sequentially while holding the same exclusive topology lock.
- No host firewall policy modification, external traffic or persistent kernel logging.

## Outcome

- Authorized scenarios: {len(allowed)}/{len(allowed)} PASS.
- Denied scenarios: {len(denied)}/{len(denied)} PASS.
- Total: {len(records)}/18 PASS.
- Audit artifacts: `{session}`.
- Session includes 18 test-before snapshots, 18 test-after snapshots,
  18 behavioral evidence JSON documents, CSV projection, JSON records and SHA-256 manifest.

| Scenario | Expected | Per-round matched packets added (R1/R2/R3) | Result |
|---|---|---|---|
{rows}

## Provenance and reproducibility

- `scripts/v08_evidence_validator.py` independently validated all 18 records,
  counter monotonicity, scenario consistency, CSV projection and manifest SHA-256.
- Evidence `data_origin` field: `LIVE_ISOLATED_NETWORK`; this is a lab-generated
  declaration, not cryptographic proof of external authenticity.
- Root scripts are executed from the root-owned reviewed staging directory.
- Original audit plan: `tests/v08_audit_plan.json`.
- Experiment design: `docs/V0.8_AUDIT_DESIGN.md`.
- Earlier failed empty snapshot evidence, if present, is retained as failed-attempt history.
- Post-test network namespace inventory empty and project deployment state absent.

## Limitations

- Counters are aggregate packet/byte counts, not identities or individual event logs.
- A positive shared `drop` counter by itself cannot attribute packets to a flow.
- Isolated sequential execution and behavior observations improve but do not prove
  attribution in the presence of unknown concurrent processes.
- Three ordered rounds cannot establish statistical significance or production behavior.
- Test services are temporary HTTP servers; port 5432 is not PostgreSQL.
- The project demonstrates network microsegmentation/audit, not a complete
  production Zero Trust architecture or continuous monitoring service.

## Next release

V0.9: release-candidate end-to-end reproducibility and repository review.
'''
    REPORT.parent.mkdir(parents=True,exist_ok=True)
    save(REPORT, report)
    print(f'REPORT_PATH={REPORT}',flush=True)

def local_commit(session):
    print('=== V0.8 LOCAL GIT RELEASE ===',flush=True)
    paths = [
        'docs/V0.8_AUDIT_DESIGN.md', 'tests/v08_audit_plan.json',
        'scripts/v08_counter_parser.py','scripts/v08_counter_delta.py',
        'scripts/v08_evidence_validator.py','scripts/v08_live_snapshot.py',
        'scripts/v08_root_audit_case.py','scripts/v08_finish_release.py',
        'reports/V0.8_EXPERIMENT_REPORT.md','evidence/v08_runs/',
    ]
    # Fail on additional modified tracked files. Do not stage unrelated paths.
    require(command(['git','diff','--quiet']).returncode == 0,'unexpected tracked edits before commit')
    require(command(['git','diff','--cached','--quiet']).returncode == 0,'index not initially empty')
    run_checked(['git','add','--']+paths,'stage release',30)
    run_checked(['git','-c','core.whitespace=cr-at-eol,-blank-at-eof',
                 '-c','core.pager=cat','diff','--cached','--check'],
                'staged whitespace review',30)
    print('V08_GIT_STAGE=PASS',flush=True)
    output = run_checked(['git','-c','core.pager=cat','commit','-m',
                          'V0.8: validate isolated firewall audit and reproducibility'],
                         'Git commit',60)
    print(output.splitlines()[0],flush=True)
    status = run_checked(['git','status','--porcelain'],'Git worktree status',15)
    require(not status.strip(),f'Git worktree not clean: {status[:400]}')
    print('V08_GIT_WORKTREE=CLEAN',flush=True)
    print('V08_COMMIT='+run_checked(['git','rev-parse','--short','HEAD'],'Git commit ID').strip(),
          flush=True)

def execute(plan, commit):
    root_preflight()
    EVIDENCE_BASE.mkdir(parents=True, exist_ok=True)
    require(not EVIDENCE_BASE.is_symlink(), 'unsafe evidence directory')
    session = EVIDENCE_BASE / ('audit_' + utcstamp() + '_' + str(os.getpid()))
    session.mkdir(mode=0o700)
    print(f'SESSION_DIR={session}',flush=True)
    # imports of our checked unprivileged files only
    sys.path.insert(0, str(Path('scripts').resolve()))
    from v08_counter_delta import compare
    from v08_evidence_validator import CSV_FIELDS, validate_session, rebuild_manifest
    records = []
    deployed = False
    issues = []
    token = None
    try:
        print('=== DEPLOY ISOLATED TOPOLOGY ===',flush=True)
        print(sudo(['timeout','--signal=TERM','--kill-after=10s','70s','bash',ROOT_UP],
                   'topology deployment',85).strip(),flush=True)
        deployed = True
        print('TOPOLOGY_DEPLOYED=PASS',flush=True)
        print(sudo(['timeout','--signal=TERM','--kill-after=10s','45s','bash',ROOT_POLICY],
                   'load firewall',60).strip(),flush=True)
        print('SEGMENTED_POLICY_LOADED=PASS',flush=True)
        for round_number in range(1,4):
            for scenario in plan['scenarios']:
                case_id=scenario['id']
                print(f'CASE_START=r{round_number}:{case_id}',flush=True)
                raw = sudo(['timeout','--signal=TERM','--kill-after=4s','35s',
                            '/usr/bin/python3','-I','-B',ROOT_CASE,'--execute',
                            case_id,str(round_number)],
                           f'audit case {case_id} R{round_number}',45)
                result=json.loads(raw)
                require(result.get('case_id')==case_id and result.get('round')==round_number,
                        'runner returned incorrect scenario')
                require(isinstance(result.get('deployment_token'),str) and
                        result['deployment_token'], 'missing topology session identity')
                if token is None:
                    token=result['deployment_token']
                require(token==result['deployment_token'],
                        'different topology sessions combined')
                expected=scenario['expected_counter']
                delta=compare(result['before'],result['after'],expected)
                require(delta['expected_counter_packets_increased'] is True,
                        f'counter did not increase for {case_id}')
                behavior=result['behavior']
                require(behavior.get('scenario_id')==case_id and
                        behavior.get('round')==round_number and
                        behavior.get('observed_behavior')==scenario['expected_verdict']
                        and behavior.get('result')=='PASS' and
                        behavior.get('exit_code')==0,
                        f'behavior evidence mismatch: {case_id}')
                prefix=f'r{round_number}_{case_id}'
                before_file=prefix+'.before.json'
                after_file=prefix+'.after.json'
                behavior_file=prefix+'.behavior.json'
                json_save(session/before_file,result['before'])
                json_save(session/after_file,result['after'])
                json_save(session/behavior_file,behavior)
                row={
                    'round':round_number, 'scenario_id':case_id,
                    'expected_verdict':scenario['expected_verdict'],
                    'observed_behavior':behavior['observed_behavior'],
                    'test_status':'PASS', 'expected_counter':expected,
                    **delta['deltas'][expected],
                    'timestamp_utc':iso_utc(),
                    'before_file':before_file,'after_file':after_file,
                    'behavior_file':behavior_file,
                }
                require(set(row)==set(CSV_FIELDS),'unexpected record fields')
                records.append(row)
                print(f'CASE_PASS=r{round_number}:{case_id}|PACKET_DELTA={row["packet_delta"]}',
                      flush=True)
    except (Exception,KeyboardInterrupt) as exc:
        issues.append(f'audit failure: {exc}')
        print(f'V08_RUN_ERROR={exc}',file=sys.stderr,flush=True)
    finally:
        if deployed:
            print('=== GUARDED TOPOLOGY CLEANUP ===',flush=True)
            try:
                print(sudo(['timeout','--signal=TERM','--kill-after=10s','90s',
                            'bash',ROOT_DOWN], 'topology cleanup',105).strip(),flush=True)
            except Exception as exc:
                issues.append(f'cleanup runner failed: {exc}')
                print(f'V08_CLEANUP_ERROR={exc}',file=sys.stderr,flush=True)
        if clean_state():
            print('V08_FINAL_CLEANUP=PASS',flush=True)
        else:
            issues.append('Namespaces or deployment state remain; inspect manually')
            print('V08_FINAL_CLEANUP=FAIL',file=sys.stderr,flush=True)
    if issues:
        raise ReleaseError(' ; '.join(issues))
    require(len(records)==18,'incomplete scenario count')
    json_save(session/'audit_records.json',{
        'schema_version':'1.0','data_origin':'LIVE_ISOLATED_NETWORK','records':records})
    with (session/'audit_records.csv').open('x',encoding='utf-8',newline='') as handle:
        writer=csv.DictWriter(handle,fieldnames=CSV_FIELDS,lineterminator='\n')
        writer.writeheader()
        writer.writerows(records)
    rebuild_manifest(session,'LIVE_ISOLATED_NETWORK')
    require(validate_session(session,plan)==18,'evidence validation did not account for 18 cases')
    print('V08_LIVE_EVIDENCE_VALIDATION=PASS',flush=True)
    print('VERIFIED_AUDIT_CASES=18/18',flush=True)
    create_report(session,records)
    if commit:
        local_commit(session)
    print('V08_EXPERIMENT_COMPLETE=PASS',flush=True)
    if commit:
        print('V08_RELEASE_COMPLETE=PASS',flush=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check',action='store_true')
    group.add_argument('--execute',action='store_true')
    parser.add_argument('--commit',action='store_true',help='commit only if --execute passes')
    args=parser.parse_args()
    require(not args.commit or args.execute,'--commit requires --execute')
    plan=validate_sources()
    if args.check:
        print('V08_FINISH_PREFLIGHT=PASS')
        print('NETWORK_TESTS_EXECUTED=0')
        return
    execute(plan,args.commit)

if __name__=='__main__':
    try:
        main()
    except (ReleaseError, OSError, ValueError, KeyError, TypeError,
            json.JSONDecodeError) as exc:
        print(f'V08_FINISH_ERROR={exc}',file=sys.stderr,flush=True)
        sys.exit(1)
