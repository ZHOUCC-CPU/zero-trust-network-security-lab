#!/usr/bin/env bash
# V0.7: reviewed, isolated single-flow performance probe runner.
# Execute ONLY from /root/ztlab-v03-reviewed after ownership/hash review.
# Invocation: bash v07_root_benchmark_runner.sh baseline|segmented latency|throughput FLOW_ID
set -Eeuo pipefail
umask 077

fail() { printf 'V07_RUNNER_ERROR=%s\n' "$*" >&2; exit 2; }
[[ $# -eq 3 ]] || fail 'Expected: CONDITION KIND FLOW_ID'
condition=$1
kind=$2
flow=$3
[[ $condition == baseline || $condition == segmented ]] || fail 'Invalid condition'
[[ $kind == latency || $kind == throughput ]] || fail 'Invalid kind'
case $flow in
    employee_to_app_tcp8080)
        src=employee-ns; dst=app-ns; dstip=10.200.20.2; port=8080 ;;
    app_to_data_tcp5432)
        src=app-ns; dst=data-ns; dstip=10.200.30.2; port=5432 ;;
    *) fail 'Unrecognized flow' ;;
esac

[[ $EUID -eq 0 ]] || fail 'Root privileges required for namespace execution'
for utility in ip nft python3 iperf3 ss sysctl timeout flock stat awk grep mktemp; do
    command -v "$utility" >/dev/null 2>&1 || fail "Missing utility: $utility"
done

rootdir=/root/ztlab-v03-reviewed
state=/var/lib/ztlab-v03/state
lock=/var/lock/ztlab-v03.lock
runner=$rootdir/v07_root_benchmark_runner.sh
latency=$rootdir/v07_tcp_latency.py
throughput=$rootdir/v07_iperf3_throughput.py
[[ -d "$rootdir" && ! -L "$rootdir" ]] || fail 'Root stage directory missing or symlinked'
[[ "$(stat -c '%u:%a' "$rootdir" 2>/dev/null)" == '0:700' ]] || fail 'Root stage directory must be root:700'
for f in "$runner" "$latency" "$throughput"; do
    [[ -f $f && ! -L $f ]] || fail "Missing or symlinked staged file: $f"
    [[ "$(stat -c '%u:%a' "$f")" == '0:700' ]] || fail "Staged file must be root:700: $f"
done
[[ -f $state && ! -L $state ]] || fail 'Missing or symlinked deployment state'
[[ "$(stat -c '%u:%a' "$state")" == '0:600' ]] || fail 'State must be root:600'
exec 9>"$lock"
flock -x -n 9 || fail 'Topology lock busy'
field() { awk -F= -v k="$1" '$1==k {print $2; exit}' "$state"; }
[[ "$(field OWNER)" == zero-trust-network-security-lab ]] || fail 'Unexpected state owner'
[[ "$(field STATE_VERSION)" == 1 && "$(field PHASE)" == ACTIVE ]] || fail 'Wrong state version/phase'
for ns in zt-gw-ns employee-ns app-ns data-ns; do
    key="NS_${ns//-/_}_INODE"
    expected=$(field "$key")
    [[ $expected =~ ^[0-9]+:[0-9]+$ ]] || fail "Invalid namespace marker: $ns"
    actual=$(stat -Lc '%d:%i' "/var/run/netns/$ns" 2>/dev/null) || fail "Missing namespace: $ns"
    [[ $actual == "$expected" ]] || fail "Namespace identity mismatch: $ns"
done
[[ "$(ip netns exec zt-gw-ns sysctl -n net.ipv4.ip_forward)" == 1 ]] || fail 'Gateway forwarding disabled'
if [[ $condition == baseline ]]; then
    tables=$(ip netns exec zt-gw-ns nft list tables) || fail 'Unable to inspect baseline firewall'
    [[ -z $tables ]] || fail 'Baseline firewall tables detected'
else
    rules=$(ip netns exec zt-gw-ns nft list chain inet ztlab_v04 forward) || fail 'Missing segmented firewall chain'
    for marker in 'policy drop;' 'ct state established,related' 'iifname "gw-emp" oifname "gw-app"' 'iifname "gw-app" oifname "gw-data"'; do
        grep -Fq "$marker" <<< "$rules" || fail "Firewall check failed: $marker"
    done
fi

# Refuse collision with any existing server in the destination namespace.
listeners=$(ip netns exec "$dst" ss -H -ltn "sport = :$port") ||
    fail "Cannot inspect listener state in $dst"

[[ -z "$listeners" ]] ||
    fail "Port $dstip:$port already has a listener"
work=$(mktemp -d /tmp/ztlab-v07-probe.XXXXXXXX) || fail 'Cannot make temporary directory'
server_pid=''
cleanup() {
    local original=$?
    trap - EXIT INT TERM
    set +e
    if [[ -n $server_pid ]]; then
        kill "$server_pid" >/dev/null 2>&1
        wait "$server_pid" >/dev/null 2>&1
    fi
    rm -f -- "$work/index.html" "$work/server.log"
    rmdir -- "$work" >/dev/null 2>&1
    exit "$original"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ $kind == latency ]]; then
    printf 'V07_HTTP_READY\n' > "$work/index.html"
    ip netns exec "$dst" timeout --signal=TERM --kill-after=2s 18s \
        python3 -m http.server "$port" --bind "$dstip" --directory "$work" \
        >"$work/server.log" 2>&1 &
    server_pid=$!
    client=$latency
else
    ip netns exec "$dst" timeout --signal=TERM --kill-after=2s 18s \
        iperf3 --server --one-off --port "$port" --bind "$dstip" \
        >"$work/server.log" 2>&1 &
    server_pid=$!
    client=$throughput
fi

# Readiness is based on a passive socket listing. Connecting would consume
# an iperf3 --one-off session and corrupt its benchmark.
ready=0
for ((attempt=0; attempt<35; attempt++)); do
    kill -0 "$server_pid" 2>/dev/null || break
    if ip netns exec "$dst" ss -H -ltn "sport = :$port" | grep -Fq "$dstip:$port"; then
        ready=1
        break
    fi
    sleep 0.1
done
if [[ $ready -ne 1 ]]; then
    cat "$work/server.log" >&2 || true
    fail 'Test server did not become ready'
fi

# The JSON result from the trusted probe is the only successful stdout.
ip netns exec "$src" timeout --signal=TERM --kill-after=2s 16s \
    python3 -I "$client" --execute --flow "$flow" || {
        cat "$work/server.log" >&2 || true
        fail "Probe failed: $condition/$kind/$flow"
    }
