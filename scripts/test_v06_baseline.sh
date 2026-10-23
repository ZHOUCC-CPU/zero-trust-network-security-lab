#!/usr/bin/env bash
# V0.6 baseline: six live scenarios without lab nftables policy.
# Stage to a root-owned directory only after security review.
set -Eeuo pipefail

GW=zt-gw-ns
STATE=/var/lib/ztlab-v03/state
LOCK=/var/lock/ztlab-v03.lock

fail() {
    echo "ERROR|preflight|$*" >&2
    exit 2
}

[[ $EUID -eq 0 ]] || fail "Root required"

for cmd in ip nft python3 flock stat awk mktemp ping; do
    command -v "$cmd" >/dev/null 2>&1 ||
        fail "Missing command: $cmd"
done

exec 9>"$LOCK"
flock -n 9 || fail "Topology lock is busy"

[[ -f "$STATE" && ! -L "$STATE" ]] ||
    fail "Active state file missing or invalid"
[[ "$(stat -c '%u:%a' "$STATE")" == "0:600" ]] ||
    fail "Invalid state ownership or permissions"

state_field() {
    awk -F= -v k="$1" '$1==k {print $2; exit}' "$STATE"
}

[[ "$(state_field OWNER)" == "zero-trust-network-security-lab" ]] ||
    fail "Invalid project owner"
[[ "$(state_field PHASE)" == "ACTIVE" ]] ||
    fail "Topology is not active"
[[ "$(state_field STATE_VERSION)" == "1" ]] ||
    fail "Unknown state version"

for ns in zt-gw-ns employee-ns app-ns data-ns; do
    key="NS_${ns//-/_}_INODE"
    expected=$(state_field "$key")
    [[ $expected =~ ^[0-9]+:[0-9]+$ ]] ||
        fail "Invalid namespace marker: $ns"

    actual=$(stat -Lc '%d:%i' "/var/run/netns/$ns" 2>/dev/null) ||
        fail "Namespace missing: $ns"

    [[ $actual == "$expected" ]] ||
        fail "Namespace identity mismatch: $ns"
done

# Refuse baseline testing if any nftables table exists.
tables=$(ip netns exec "$GW" nft list tables) ||
    fail "Cannot inspect gateway firewall"

[[ -z "$tables" ]] ||
    fail "Gateway has nftables tables; baseline refused"

forwarding=$(ip netns exec "$GW" \
    sysctl -n net.ipv4.ip_forward) ||
    fail "Cannot inspect forwarding"

[[ "$forwarding" == "1" ]] ||
    fail "IPv4 forwarding is disabled"

WORK_DIR=$(mktemp -d /tmp/ztlab-v06-baseline.XXXXXXXX) ||
    fail "Cannot create temporary directory"

server_pids=()

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    set +e

    for pid in "${server_pids[@]}"; do
        kill "$pid" >/dev/null 2>&1
    done
    for pid in "${server_pids[@]}"; do
        wait "$pid" >/dev/null 2>&1
    done

    rm -f -- \
        "$WORK_DIR/app8080/index.html" \
        "$WORK_DIR/app8081/index.html" \
        "$WORK_DIR/data5432/index.html" \
        "$WORK_DIR/app8080.log" \
        "$WORK_DIR/app8081.log" \
        "$WORK_DIR/data5432.log"

    rmdir -- \
        "$WORK_DIR/app8080" \
        "$WORK_DIR/app8081" \
        "$WORK_DIR/data5432" \
        "$WORK_DIR" >/dev/null 2>&1

    exit "$rc"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 700 \
    "$WORK_DIR/app8080" \
    "$WORK_DIR/app8081" \
    "$WORK_DIR/data5432"

printf 'ZT_LAB_V04_HTTP_OK\n' > "$WORK_DIR/app8080/index.html"
printf 'ZT_LAB_V04_PORT8081\n' > "$WORK_DIR/app8081/index.html"
printf 'ZT_LAB_V04_TCP5432_OK\n' > "$WORK_DIR/data5432/index.html"

start_server() {
    local name="$1" ns="$2" address="$3" port="$4" dir="$5"

    ip netns exec "$ns" \
        python3 -m http.server "$port" \
        --bind "$address" --directory "$dir" \
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

    server_ready "$ns" "$address" "$port" "${server_pids[$index]}" ||
        fail "Test service unavailable: $address:$port"
done

echo "PASS|preflight|three isolated test servers are listening"

probe_http() {
    local src="$1" address="$2" port="$3" expected="$4"

    ip netns exec "$src" python3 - "$address" "$port" "$expected" <<'PY'
import sys
import urllib.request

address, port, expected = sys.argv[1:]

try:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    )
    with opener.open(
        f"http://{address}:{port}/", timeout=5
    ) as response:
        status = response.status
        body = response.read().decode().strip()

    if status == 200 and body == expected:
        sys.exit(0)
except Exception as exc:
    print(f"HTTP probe error: {exc}", file=sys.stderr)

sys.exit(1)
PY
}

passed=0
failed=0

record() {
    local verdict="$1" label="$2" detail="$3"

    printf '%s|%s|%s\n' "$verdict" "$label" "$detail"

    if [[ "$verdict" == PASS ]]; then
        passed=$((passed+1))
    else
        failed=$((failed+1))
    fi
}

run_http() {
    local label="$1" src="$2" address="$3" port="$4" body="$5"

    if probe_http "$src" "$address" "$port" "$body"; then
        record PASS "$label" "Baseline HTTP 200 with expected body"
    else
        record FAIL "$label" "Baseline HTTP probe unsuccessful"
    fi
}

run_ping() {
    if ip netns exec employee-ns \
        ping -n -c 2 -W 1 10.200.30.2 >/dev/null 2>&1; then
        record PASS employee_to_data_icmp "Baseline ICMP reachable"
    else
        record FAIL employee_to_data_icmp "Baseline ICMP unsuccessful"
    fi
}

echo "=== V0.6 BASELINE SIX-SCENARIO TEST ==="

run_http employee_to_app_tcp8080 employee-ns \
    10.200.20.2 8080 ZT_LAB_V04_HTTP_OK

run_http app_to_data_tcp5432 app-ns \
    10.200.30.2 5432 ZT_LAB_V04_TCP5432_OK

run_ping

run_http employee_to_data_tcp5432 employee-ns \
    10.200.30.2 5432 ZT_LAB_V04_TCP5432_OK

run_http employee_to_app_tcp8081 employee-ns \
    10.200.20.2 8081 ZT_LAB_V04_PORT8081

run_http data_to_app_tcp8080 data-ns \
    10.200.20.2 8080 ZT_LAB_V04_HTTP_OK

printf 'SUMMARY|passed|%d\n' "$passed"
printf 'SUMMARY|failed|%d\n' "$failed"

if ((passed == 6 && failed == 0)); then
    echo "BASELINE_RESULT=PASS"
    exit 0
fi

echo "BASELINE_RESULT=FAIL"
exit 1
