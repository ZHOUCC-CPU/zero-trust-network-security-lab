#!/usr/bin/env bash
# Unprivileged coordinator: privileged scripts execute ONLY from reviewed root staging.
set -Eeuo pipefail
umask 077
[[ $# == 1 && $1 == --run ]] || { echo 'USAGE: bash scripts/v09_live_trial.sh --run' >&2; exit 2; }
[[ $EUID -ne 0 ]] || { echo 'STOP: run as normal WSL user, not root' >&2; exit 2; }
[[ -f scripts/v09_resource_integrity.py && -f scripts/v08_counter_parser.py ]] || { echo 'STOP: run from project root' >&2; exit 2; }
[[ $(git rev-parse --short HEAD) == cb7c124 ]] || { echo 'STOP: unexpected baseline commit' >&2; exit 2; }
python3 -B - <<'PY_CHECK_STATUS'
import subprocess
actual = set(subprocess.check_output(
    ['git', 'status', '--porcelain', '--untracked-files=all'], text=True
).splitlines())
expected = {
    ' M PROJECT_ROADMAP.md', ' M README.md',
    '?? docs/V0.9_REPRODUCIBILITY_CHECKLIST.md',
    '?? scripts/v09_resource_integrity.py',
    '?? tests/test_v09_resource_integrity.py',
    '?? scripts/v09_live_trial.sh',
}
if actual != expected:
    print('STOP: unexpected Git status: ' + repr(sorted(actual)))
    raise SystemExit(2)
print('V09_TRIAL_GIT_BASELINE=PASS')
PY_CHECK_STATUS
ROOT=/root/ztlab-v03-reviewed
STATE=/var/lib/ztlab-v03/state
LOCK=/var/lock/ztlab-v03.lock
UP="$ROOT/topology_up.sh"
DOWN="$ROOT/topology_down.sh"
POLICY="$ROOT/load_v04_policy.sh"
TEST="$ROOT/test_v04_firewall.sh"

# Read-only preflight; never overwrite or repair unknown experiment resources.
sudo -v
python3 -B scripts/v09_resource_integrity.py --check || { echo 'STOP: resources are not clean' >&2; exit 2; }
sudo -n test -d "$ROOT" && sudo -n test ! -L "$ROOT" || exit 2
[[ $(sudo -n stat -c '%u:%g:%a' "$ROOT") == 0:0:700 ]] || exit 2
for item in topology_up.sh load_v04_policy.sh test_v04_firewall.sh; do
    sudo -n test -f "$ROOT/$item" && sudo -n test ! -L "$ROOT/$item" || exit 2
    [[ $(sudo -n stat -c '%u:%g:%a' "$ROOT/$item") == 0:0:700 ]] || exit 2
    sudo -n cmp -s "scripts/$item" "$ROOT/$item" || { echo "STOP: staged mismatch $item" >&2; exit 2; }
done
sudo -n test -f "$ROOT/v04_gateway_filter.nft" && sudo -n test ! -L "$ROOT/v04_gateway_filter.nft" || exit 2
sudo -n cmp -s deployment/v04_gateway_filter.nft "$ROOT/v04_gateway_filter.nft" || { echo 'STOP: staged policy mismatch' >&2; exit 2; }
[[ $(sudo -n stat -c '%u:%g:%a' "$ROOT/v04_gateway_filter.nft") == 0:0:600 ]] || exit 2
sudo -n test -f "$DOWN" && sudo -n test ! -L "$DOWN" || exit 2
[[ $(sudo -n stat -c '%u:%g:%a' "$DOWN") == 0:0:700 ]] || exit 2
[[ $(sudo -n sha256sum "$DOWN" | awk '{print $1}') == 8a71b3bf81bd9267f95ef264c1593ce8ae15ac74811f576d02819d4ddf301080 ]] || { echo 'STOP: unapproved cleanup script' >&2; exit 2; }
[[ $(sudo -n stat -c '%u:%g:%a' "$LOCK") == 0:0:644 ]] || exit 2
sudo -n test -f "$LOCK" && sudo -n test ! -L "$LOCK" || exit 2

parent=evidence/v09_runs
[[ ! -L $parent ]] || { echo 'STOP: evidence parent is a symlink' >&2; exit 2; }
mkdir -p -- "$parent"
SESSION="$parent/trial_$(date -u +%Y%m%dT%H%M%S%NZ)_$$"
mkdir -- "$SESSION" || exit 2
printf 'SESSION_DIR=%s\n' "$SESSION"
attempted=0
cleanup() {
    local original=$? down_rc=0 check_rc=0 manifest_rc=0
    trap - EXIT INT TERM
    set +e
    if (( attempted )); then
        echo '=== GUARDED NETWORK CLEANUP ==='
        if sudo -n test -f "$STATE"; then
            sudo -n timeout --signal=TERM --kill-after=10s 100s bash "$DOWN" > "$SESSION/cleanup.log" 2>&1
            down_rc=$?
        else
            printf 'No state marker; guarded cleanup unavailable. Checking residual resources.\n' > "$SESSION/cleanup.log"
        fi
        cat "$SESSION/cleanup.log"
    fi
    python3 -B scripts/v09_resource_integrity.py --check > "$SESSION/postcheck.log" 2>&1
    check_rc=$?
    cat "$SESSION/postcheck.log"
    python3 - "$SESSION" <<'PY'
import hashlib, json, pathlib, sys
session = pathlib.Path(sys.argv[1])
files = sorted(p for p in session.iterdir() if p.is_file() and p.name != 'manifest.sha256')
(session / 'manifest.sha256').write_text(''.join(
    f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files
), encoding='utf-8')
print('V09_EVIDENCE_MANIFEST_WRITTEN=PASS')
PY
    manifest_rc=$?
    if (( original || down_rc || check_rc || manifest_rc )); then
        printf 'V09_TRIAL=FAIL|RUN=%d|CLEANUP=%d|RESOURCE_CHECK=%d|MANIFEST=%d\n' "$original" "$down_rc" "$check_rc" "$manifest_rc" >&2
        exit 1
    fi
    echo 'V09_TRIAL=PASS'
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Baseline=%s\nUTC=%s\n' "$(git rev-parse HEAD)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$SESSION/environment.txt"
printf '=== DEPLOY TOPOLOGY ===\n'
attempted=1
sudo -n timeout --signal=TERM --kill-after=10s 90s bash "$UP" 2>&1 | tee "$SESSION/deploy.log"
printf '=== LOAD GATEWAY POLICY ===\n'
sudo -n timeout --signal=TERM --kill-after=10s 60s bash "$POLICY" 2>&1 | tee "$SESSION/policy.log"
for round in 1 2 3; do
    echo "=== LIVE REGRESSION ROUND $round / 3 ==="
    sudo -n ip netns exec zt-gw-ns nft -j list chain inet ztlab_v04 forward > "$SESSION/round${round}.before.nft.json"
    sudo -n timeout --signal=TERM --kill-after=10s 120s bash "$TEST" 2>&1 | tee "$SESSION/round${round}.test.log"
    grep -Fxq 'SUMMARY|passed|6' "$SESSION/round${round}.test.log"
    grep -Fxq 'SUMMARY|failed|0' "$SESSION/round${round}.test.log"
    grep -Fxq 'REGRESSION_RESULT=PASS' "$SESSION/round${round}.test.log"
    sudo -n ip netns exec zt-gw-ns nft -j list chain inet ztlab_v04 forward > "$SESSION/round${round}.after.nft.json"
done
python3 -B - "$SESSION" <<'PY'
import json, pathlib, sys
sys.path.insert(0, 'scripts')
from v08_counter_delta import compare
session = pathlib.Path(sys.argv[1])
results = []
for round_num in (1, 2, 3):
    before = json.loads((session / f'round{round_num}.before.nft.json').read_text())
    after = json.loads((session / f'round{round_num}.after.nft.json').read_text())
    change = compare(before, after)
    increments = {name: values['packet_delta'] for name, values in change['deltas'].items()}
    if not all(increments.get(name, 0) > 0 for name in ('allow_emp_app', 'allow_app_data', 'drop')):
        raise SystemExit(f'STOP: expected packet counter not increased in round {round_num}: {increments}')
    results.append({'round': round_num, 'packet_deltas': increments})
    print(f'ROUND_{round_num}_RULE_DELTA=PASS|{increments}', flush=True)
(session / 'counter_deltas.json').write_text(json.dumps(results, indent=2, sort_keys=True) + '\n')
print('V09_NETWORK_SCENARIOS=18/18_PASS')
PY
