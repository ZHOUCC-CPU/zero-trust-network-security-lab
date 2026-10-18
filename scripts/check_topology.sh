#!/usr/bin/env bash
set -Eeuo pipefail

# Read-only V0.3 inspection. This script never changes network configuration.
readonly STATE_DIR="/var/lib/ztlab-v03"
readonly STATE_FILE="$STATE_DIR/state"
readonly LOCK_FILE="/var/lock/ztlab-v03.lock"
readonly GW_NS="zt-gw-ns"
readonly NS=(employee-ns app-ns data-ns zt-gw-ns)
failures=0

pass() { printf 'PASS|%s|%s\n' "$1" "$2"; }
fail() { printf 'FAIL|%s|%s\n' "$1" "$2"; failures=$((failures + 1)); }
note() { printf 'INFO|%s|%s\n' "$1" "$2"; }
ns_exists() { ip netns list | awk '{print $1}' | grep -Fxq "$1"; }
has_exact_addr() { ip -n "$1" -o -4 addr show dev "$2" | awk '{print $4}' | grep -Fxq "$3"; }
has_route() {
    ip -n "$1" -4 route show |
        awk -v expected="$2" '{
            sub(/[[:space:]]+$/, "", $0)
            if ($0 == expected) found=1
        } END {
            exit(found ? 0 : 1)
        }'
}
has_iface() { ip -n "$1" link show dev "$2" >/dev/null 2>&1; }
is_veth() { ip -n "$1" -d link show dev "$2" 2>/dev/null | grep -Fq 'veth'; }
state_value() { awk -F= -v wanted="$1" '$1 == wanted { print substr($0, index($0, "=") + 1); exit }' "$STATE_FILE"; }
check() { if "$@"; then pass "$1" "${*:2}"; else fail "$1" "${*:2}"; fi; }
ping_from() { ip netns exec "$1" ping -c 1 -W 1 -n "$2" >/dev/null 2>&1; }

[[ ${EUID} -eq 0 ]] || { printf 'ERROR|preflight|root privileges are required\n' >&2; exit 1; }
command -v ip >/dev/null 2>&1 || { printf 'ERROR|preflight|ip command not found\n' >&2; exit 1; }
command -v ping >/dev/null 2>&1 || { printf 'ERROR|preflight|ping command not found\n' >&2; exit 1; }
command -v stat >/dev/null 2>&1 || { printf 'ERROR|preflight|stat command not found\n' >&2; exit 1; }
command -v flock >/dev/null 2>&1 || { printf 'ERROR|preflight|flock command not found\n' >&2; exit 1; }
exec 9>"$LOCK_FILE"
flock -s -n 9 || { printf 'ERROR|lock|another topology operation is running\n' >&2; exit 1; }

for ns in "${NS[@]}"; do
  if ns_exists "$ns"; then pass namespace "exists: $ns"; else fail namespace "missing: $ns"; fi
done
check has_iface "$GW_NS" gw-emp; check has_iface "$GW_NS" gw-app; check has_iface "$GW_NS" gw-data
check has_iface employee-ns emp-gw; check has_iface app-ns app-gw; check has_iface data-ns data-gw
check is_veth "$GW_NS" gw-emp; check is_veth "$GW_NS" gw-app; check is_veth "$GW_NS" gw-data
check is_veth employee-ns emp-gw; check is_veth app-ns app-gw; check is_veth data-ns data-gw
check has_exact_addr "$GW_NS" gw-emp 10.200.10.1/30
check has_exact_addr employee-ns emp-gw 10.200.10.2/30
check has_exact_addr "$GW_NS" gw-app 10.200.20.1/30
check has_exact_addr app-ns app-gw 10.200.20.2/30
check has_exact_addr "$GW_NS" gw-data 10.200.30.1/30
check has_exact_addr data-ns data-gw 10.200.30.2/30

check has_route employee-ns '10.200.20.0/30 via 10.200.10.1 dev emp-gw'
check has_route employee-ns '10.200.30.0/30 via 10.200.10.1 dev emp-gw'
check has_route app-ns '10.200.10.0/30 via 10.200.20.1 dev app-gw'
check has_route app-ns '10.200.30.0/30 via 10.200.20.1 dev app-gw'
check has_route data-ns '10.200.10.0/30 via 10.200.30.1 dev data-gw'
check has_route data-ns '10.200.20.0/30 via 10.200.30.1 dev data-gw'

if [[ "$(ip netns exec "$GW_NS" sysctl -n net.ipv4.ip_forward 2>/dev/null)" == 1 ]]; then
  pass forwarding 'zt-gw-ns IPv4 forwarding is enabled'
else
  fail forwarding 'zt-gw-ns IPv4 forwarding is not enabled'
fi

check ping_from employee-ns 10.200.10.1; check ping_from app-ns 10.200.20.1; check ping_from data-ns 10.200.30.1
note reachability 'The three zone-to-gateway checks are topology checks, not authorization tests.'
check ping_from employee-ns 10.200.20.2
check ping_from employee-ns 10.200.30.2
check ping_from app-ns 10.200.30.2
note access-control 'V0.3 has no firewall policy; cross-zone reachability is expected topology behavior and must not be interpreted as an access-control failure.'

if [[ -d "$STATE_DIR" && "$(stat -c '%u:%a' -- "$STATE_DIR" 2>/dev/null)" == '0:700' && -f "$STATE_FILE" && "$(stat -c '%u:%a' -- "$STATE_FILE" 2>/dev/null)" == '0:600' && "$(state_value STATE_VERSION)" == 1 && "$(state_value OWNER)" == zero-trust-network-security-lab ]]; then
  pass ownership "valid root-owned state marker: $STATE_FILE"
else
  fail ownership 'state directory/file is missing or has invalid owner, mode, version, or owner marker'
fi
printf 'SUMMARY|topology_failures|%d\n' "$failures"
(( failures == 0 ))
