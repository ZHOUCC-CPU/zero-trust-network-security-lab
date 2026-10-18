#!/usr/bin/env bash
# V0.4 firewall behavioral regression: six live, isolated-network scenarios.
# Runs three short-lived HTTP test servers and cleans them up on exit.
# It does not change nftables rules, routes, interfaces, or namespaces.
set -Eeuo pipefail

GW=zt-gw-ns
STATE=/var/lib/ztlab-v03/state
LOCK=/var/lock/ztlab-v03.lock
TABLE=ztlab_v04

fail() { printf 'ERROR|preflight|%s\n' "$*" >&2; exit 2; }
[[ $EUID -eq 0 ]] || fail 'Run as root (sudo).'
for cmd in ip nft python3 flock stat awk grep mktemp; do
    command -v "$cmd" >/dev/null 2>&1 || fail "Missing command: $cmd"
done

# Share the topology lock with the V0.3/V0.4 deployment scripts.
exec 9>"$LOCK"
flock -s -n 9 || fail 'A topology operation currently holds the lock.'
[[ -f $STATE ]] || fail 'The V0.3 topology is not deployed.'
[[ $(stat -c '%u:%a' "$STATE") == 0:600 ]] || fail 'Unexpected state ownership/permissions.'

state_field() { awk -F= -v k="$1" '$1==k {print $2; exit}' "$STATE"; }
[[ $(state_field OWNER) == zero-trust-network-security-lab ]] || fail 'Wrong state owner.'
[[ $(state_field PHASE) == ACTIVE ]] || fail 'Topology is not ACTIVE.'
[[ $(state_field STATE_VERSION) == 1 ]] || fail 'Unrecognized state version.'
for ns in zt-gw-ns employee-ns app-ns data-ns; do
    key="NS_${ns//-/_}_INODE"
    expected=$(state_field "$key")
    [[ $expected =~ ^[0-9]+:[0-9]+$ ]] || fail "Invalid namespace marker: $ns"
    actual=$(stat -Lc '%d:%i' "/var/run/netns/$ns" 2>/dev/null) || fail "Namespace absent: $ns"
    [[ $actual == "$expected" ]] || fail "Namespace identity mismatch: $ns"
done

# Check the expected gateway chain before sending test traffic.
get_rules() { ip netns exec "$GW" nft list chain inet "$TABLE" forward; }
rules=$(get_rules) || fail 'Cannot read V0.4 forward chain.'
grep -q 'policy drop;' <<< "$rules" || fail 'The forwarding chain is not default-deny.'
grep -Fq 'ct state established,related' <<< "$rules" || fail 'Return-flow rule is missing.'
grep -Fq 'iifname "gw-emp" oifname "gw-app"' <<< "$rules" || fail 'Employee-to-App rule is missing.'
grep -Fq 'iifname "gw-app" oifname "gw-data"' <<< "$rules" || fail 'App-to-Data rule is missing.'
grep -Eq 'counter packets [0-9]+ bytes [0-9]+ drop' <<< "$rules" || fail 'Drop counter rule is missing.'

# Return the packet counter for an expected rule, verifying one match exists.
counter_packets() {
    local kind="$1" lines value
    lines=$(get_rules) || return 1
    case "$kind" in
        emp_app) lines=$(grep -F 'iifname "gw-emp" oifname "gw-app"' <<< "$lines" | grep -F 'tcp dport 8080') ;;
        app_data) lines=$(grep -F 'iifname "gw-app" oifname "gw-data"' <<< "$lines" | grep -F 'tcp dport 5432') ;;
        drop) lines=$(grep -E 'counter packets [0-9]+ bytes [0-9]+ drop' <<< "$lines") ;;
        *) return 1 ;;
    esac
    [[ $(wc -l <<< "$lines") -eq 1 ]] || return 1
    value=$(awk '{for (i=1;i<=NF-2;i++) if ($i=="counter" && $(i+1)=="packets") {print $(i+2); exit}}' <<< "$lines")
    [[ $value =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$value"
}

for kind in emp_app app_data drop; do
    counter_packets "$kind" >/dev/null || fail "Cannot find unique rule counter: $kind"
done

WORK_DIR=$(mktemp -d /tmp/ztlab-v04-regression.XXXXXXXX) || fail 'Cannot create temp directory.'
server_pids=()
cleanup() {
    local original_rc=$?
    trap - EXIT INT TERM
    set +e
    for pid in "${server_pids[@]}"; do kill "$pid" >/dev/null 2>&1; done
    for pid in "${server_pids[@]}"; do wait "$pid" >/dev/null 2>&1; done
    rm -f -- "$WORK_DIR"/app8080/index.html "$WORK_DIR"/app8081/index.html "$WORK_DIR"/data5432/index.html
    rm -f -- "$WORK_DIR"/*.log
    rmdir -- "$WORK_DIR"/app8080 "$WORK_DIR"/app8081 "$WORK_DIR"/data5432 "$WORK_DIR" >/dev/null 2>&1
    rmdir -- "$WORK_DIR" >/dev/null 2>&1
    exit "$original_rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 700 "$WORK_DIR/app8080" "$WORK_DIR/app8081" "$WORK_DIR/data5432"
printf 'ZT_LAB_V04_HTTP_OK\n' > "$WORK_DIR/app8080/index.html"
printf 'ZT_LAB_V04_PORT8081\n' > "$WORK_DIR/app8081/index.html"
printf 'ZT_LAB_V04_TCP5432_OK\n' > "$WORK_DIR/data5432/index.html"

start_server() {
    local name="$1" ns="$2" address="$3" port="$4" dir="$5"
    ip netns exec "$ns" python3 -m http.server "$port" --bind "$address" --directory "$dir" \
        >"$WORK_DIR/$name.log" 2>&1 &
    server_pids+=("$!")
}

start_server app8080 app-ns 10.200.20.2 8080 "$WORK_DIR/app8080"
start_server app8081 app-ns 10.200.20.2 8081 "$WORK_DIR/app8081"
start_server data5432 data-ns 10.200.30.2 5432 "$WORK_DIR/data5432"

server_ready() {
    local ns="$1" address="$2" port="$3" pid="$4" i
    for ((i=0; i<25; i++)); do
        kill -0 "$pid" 2>/dev/null || return 1
        if ip netns exec "$ns" python3 -c \
            'import socket,sys; socket.create_connection((sys.argv[1],int(sys.argv[2])),0.35).close()' \
            "$address" "$port" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

for entry in \
    'app-ns 10.200.20.2 8080 0' \
    'app-ns 10.200.20.2 8081 1' \
    'data-ns 10.200.30.2 5432 2'; do
    read -r ns address port index <<< "$entry"
    if ! server_ready "$ns" "$address" "$port" "${server_pids[$index]}"; then
        printf 'ERROR|server|%s:%s failed to start\n' "$address" "$port" >&2
        cat "$WORK_DIR"/*.log >&2
        exit 2
    fi
done
printf 'PASS|preflight|three isolated test servers are listening\n'

allow_http() {
    local src="$1" address="$2" port="$3" expected="$4"
    ip netns exec "$src" python3 - "$address" "$port" "$expected" <<'PY'
import sys, urllib.request
address, port, expected = sys.argv[1:]
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://{address}:{port}/", timeout=5) as response:
        status = response.status
        body = response.read().decode().strip()
    if status == 200 and body == expected:
        sys.exit(0)
    print(f"Unexpected response: status={status}, body={body!r}", file=sys.stderr)
except Exception as exc:
    print(f"HTTP request failed: {exc}", file=sys.stderr)
sys.exit(1)
PY
}

deny_tcp() {
    local src="$1" address="$2" port="$3"
    ip netns exec "$src" python3 - "$address" "$port" <<'PY'
import socket, sys
try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3):
        pass
except socket.timeout:
    sys.exit(0)
except OSError as exc:
    print(f"Inconclusive TCP error: {exc}", file=sys.stderr)
    sys.exit(2)
print('Unexpected TCP connection success.', file=sys.stderr)
sys.exit(1)
PY
}

passed=0
failed=0
record() {
    local verdict="$1" label="$2" detail="$3"
    printf '%s|%s|%s\n' "$verdict" "$label" "$detail"
    if [[ $verdict == PASS ]]; then passed=$((passed+1)); else failed=$((failed+1)); fi
}

run_allow() {
    local label="$1" src="$2" ipaddr="$3" port="$4" body="$5" kind="$6" before after
    before=$(counter_packets "$kind") || fail "Missing $kind counter."
    if allow_http "$src" "$ipaddr" "$port" "$body"; then
        after=$(counter_packets "$kind") || fail "Missing $kind counter."
        if ((after > before)); then
            record PASS "$label" "HTTP 200 and allow counter +$((after-before))"
        else
            record FAIL "$label" 'HTTP succeeded but allow counter did not increase'
        fi
    else
        record FAIL "$label" 'Authorized HTTP request failed'
    fi
}

run_deny() {
    local label="$1" src="$2" ipaddr="$3" port="$4" before after status=0
    before=$(counter_packets drop) || fail 'Missing drop counter.'
    deny_tcp "$src" "$ipaddr" "$port" || status=$?
    after=$(counter_packets drop) || fail 'Missing drop counter.'
    if ((status == 0 && after > before)); then
        record PASS "$label" "TCP timed out and drop counter +$((after-before))"
    else
        record FAIL "$label" "TCP result=$status; drop counter change=$((after-before))"
    fi
}

run_ping_deny() {
    local before after status=0
    before=$(counter_packets drop) || fail 'Missing drop counter.'
    ip netns exec employee-ns ping -n -c 2 -W 1 10.200.30.2 >/dev/null 2>&1 || status=$?
    after=$(counter_packets drop) || fail 'Missing drop counter.'
    if ((status != 0 && after > before)); then
        record PASS employee_to_data_icmp "ping failed and drop counter +$((after-before))"
    else
        record FAIL employee_to_data_icmp "ping status=$status; drop counter change=$((after-before))"
    fi
}

printf '%s\n' '=== V0.4 SIX-SCENARIO REGRESSION ==='
run_allow employee_to_app_tcp8080 employee-ns 10.200.20.2 8080 ZT_LAB_V04_HTTP_OK emp_app
run_allow app_to_data_tcp5432 app-ns 10.200.30.2 5432 ZT_LAB_V04_TCP5432_OK app_data
run_ping_deny
run_deny employee_to_data_tcp5432 employee-ns 10.200.30.2 5432
run_deny employee_to_app_tcp8081 employee-ns 10.200.20.2 8081
run_deny data_to_app_tcp8080 data-ns 10.200.20.2 8080
printf 'SUMMARY|passed|%d\nSUMMARY|failed|%d\n' "$passed" "$failed"
if ((failed == 0 && passed == 6)); then
    printf 'REGRESSION_RESULT=PASS\n'
    exit 0
fi
printf 'REGRESSION_RESULT=FAIL\n'
exit 1
