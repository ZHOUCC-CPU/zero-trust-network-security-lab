#!/usr/bin/env bash
set -Eeuo pipefail

# V0.3 topology only. This script does not configure nftables, NAT, or egress.
readonly STATE_DIR="/var/lib/ztlab-v03"
readonly STATE_FILE="$STATE_DIR/state"
readonly LOCK_FILE="/var/lock/ztlab-v03.lock"
readonly GW_NS="zt-gw-ns"
readonly ZONE_NAMES=(employee-ns app-ns data-ns)
readonly ALL_NAMESPACES=("$GW_NS" "${ZONE_NAMES[@]}")
readonly GW_LINKS=(ztlab-emp-gw ztlab-app-gw ztlab-data-gw)
readonly ZONE_LINKS=(ztlab-gw-emp ztlab-gw-app ztlab-gw-data)
readonly ZONE_IFACES=(emp-gw app-gw data-gw)
readonly GW_IFACES=(gw-emp gw-app gw-data)
readonly NETWORKS=(10.200.10 10.200.20 10.200.30)

CREATED_NAMESPACES=()
CREATED_LINKS=()
ROLLBACK_RUNNING=0
STATE_DIR_CREATED=0
TMP_STATE=""
DEPLOY_TOKEN=""
DEPLOY_SUCCESS=0

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
ns_exists() { ip netns list | awk '{print $1}' | grep -Fxq "$1"; }
link_exists() { ip link show dev "$1" >/dev/null 2>&1; }
namespace_identity() {
  local ns=$1 value
  value="$(stat -Lc '%d:%i' -- "/var/run/netns/$ns" 2>/dev/null)" || die "cannot read namespace identity: $ns"
  [[ -n "$value" && "$value" != *$'\n'* ]] || die "empty namespace identity: $ns"
  printf '%s\n' "$value"
}
valid_identity() { [[ "$1" =~ ^[0-9]+:[0-9]+$ ]]; }
record_namespace_identity() {
  local ns=$1 identity tmp key
  if ! identity="$(namespace_identity "$ns")"; then
    die "namespace identity acquisition failed: $ns"
  fi
  valid_identity "$identity" || die "invalid namespace identity for $ns: $identity"
  key="NS_${ns//-/_}_INODE"
  tmp="$(mktemp --tmpdir="$STATE_DIR" .state.identity.XXXXXX)"
  awk -F= -v key="$key" -v value="$identity" '{ if ($1 == key) { print key "=" value; found=1 } else print } END { if (!found) print key "=" value }' "$STATE_FILE" > "$tmp"
  chmod 600 -- "$tmp"; chown root:root -- "$tmp"; mv -f -- "$tmp" "$STATE_FILE"
}
state_exists() { [[ -f "$STATE_FILE" ]]; }
validate_state_dir() {
  if [[ -e "$STATE_DIR" ]]; then
    [[ -d "$STATE_DIR" ]] || die "state path exists but is not a directory: $STATE_DIR"
    [[ "$(stat -c '%u:%a' -- "$STATE_DIR")" == '0:700' ]] || die "state directory must be root-owned with mode 700: $STATE_DIR"
  else
    install -d -o root -g root -m 700 -- "$STATE_DIR"
    STATE_DIR_CREATED=1
  fi
}

rollback() {
  local rc=${1:-$?}
  [[ $ROLLBACK_RUNNING -eq 1 ]] && return "$rc"
  ROLLBACK_RUNNING=1
  set +e
  [[ -n "$TMP_STATE" ]] && rm -f -- "$TMP_STATE"
  local failed=0

for ns in "${CREATED_NAMESPACES[@]}"; do
    if ! ns_exists "$ns"; then
        continue
    fi

    local key="NS_${ns//-/_}_INODE"
    local expected="" actual="" owner="" token="" pids=""

    if [[ -f "$STATE_FILE" ]]; then
        owner="$(awk -F= '$1 == "OWNER" {print $2; exit}' "$STATE_FILE")"
        token="$(awk -F= '$1 == "TOKEN" {print $2; exit}' "$STATE_FILE")"
        expected="$(awk -F= -v key="$key" '$1 == key {print $2; exit}' "$STATE_FILE")"
    fi

    actual="$(stat -Lc '%d:%i' -- "/var/run/netns/$ns" 2>/dev/null)" || actual=""

    if [[ "$owner" != "zero-trust-network-security-lab" ||
          -z "$DEPLOY_TOKEN" ||
          "$token" != "$DEPLOY_TOKEN" ||
          ! "$expected" =~ ^[0-9]+:[0-9]+$ ||
          "$actual" != "$expected" ]]; then
        printf 'ROLLBACK-FAIL: namespace identity cannot be verified: %s\n' "$ns" >&2
        failed=1
        continue
    fi

    if ! pids="$(ip netns pids "$ns" 2>/dev/null)"; then
        printf 'ROLLBACK-FAIL: cannot inspect processes in %s\n' "$ns" >&2
        failed=1
    elif [[ -n "$pids" ]]; then
        printf 'ROLLBACK-FAIL: namespace %s still has processes\n' "$ns" >&2
        failed=1
    elif ! ip netns del "$ns"; then
        printf 'ROLLBACK-FAIL: failed to delete namespace %s\n' "$ns" >&2
        failed=1
    fi
done

  # Check remaining host-side interfaces after namespace cleanup.
  for link in "${CREATED_LINKS[@]}"; do
    if link_exists "$link"; then
      printf 'ROLLBACK-FAIL: residual interface requires manual review: %s\n' "$link" >&2
      failed=1
    fi
  done


  state_owned_by_deploy() {
    [[ -f "$STATE_FILE" ]] || return 1
    [[ "$(awk -F= '$1 == "OWNER" {print $2; exit}' "$STATE_FILE")" == zero-trust-network-security-lab ]] || return 1
    [[ "$(awk -F= '$1 == "TOKEN" {print $2; exit}' "$STATE_FILE")" == "$DEPLOY_TOKEN" ]] || return 1
  }
  if [[ $failed -eq 0 && $DEPLOY_SUCCESS -eq 0 ]] && state_owned_by_deploy; then
    rm -f -- "$STATE_FILE"
    [[ $STATE_DIR_CREATED -eq 1 ]] && rmdir -- "$STATE_DIR" 2>/dev/null || true
  elif [[ $failed -eq 0 && $DEPLOY_SUCCESS -eq 0 ]]; then
    printf 'ROLLBACK-FAIL: state ownership changed; state retained for manual review.\n' >&2
  else
    printf 'Rollback incomplete; inspect project resources before retrying.\n' >&2
  fi
  return "$rc"
}
on_signal() { printf 'ERROR: deployment interrupted; starting guarded rollback.\n' >&2; rollback 130; exit 130; }

[[ ${EUID} -eq 0 ]] || die 'root privileges are required inside Linux'
for cmd in ip awk grep sysctl date stat install mktemp mv flock; do need_cmd "$cmd"; done
exec 9>"$LOCK_FILE"
flock -n 9 || die 'another V0.3 operation is already running'
[[ ! -e "$STATE_DIR" ]] || validate_state_dir
state_exists && die "state file already exists: $STATE_FILE; use topology_down.sh after identity validation"
for ns in "${ALL_NAMESPACES[@]}"; do ns_exists "$ns" && die "namespace name is already in use: $ns"; done
for link in "${GW_LINKS[@]}" "${ZONE_LINKS[@]}"; do link_exists "$link" && die "interface name is already in use: $link"; done
validate_state_dir


trap 'rollback $?' ERR
trap 'on_signal' INT TERM
trap 'rc=$?; if (( rc != 0 && DEPLOY_SUCCESS == 0 && ROLLBACK_RUNNING == 0 )); then rollback "$rc"; fi' EXIT

umask 077
token="$(cat /proc/sys/kernel/random/uuid)"; DEPLOY_TOKEN="$token"
TMP_STATE="$(mktemp --tmpdir="$STATE_DIR" .state.creating.XXXXXX)"
{
  printf 'STATE_VERSION=1\nOWNER=zero-trust-network-security-lab\nTOKEN=%s\n' "$token"
  printf 'PHASE=CREATING\nPID=%s\nCREATED_UTC=%s\n' "$$" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'EXPECTED_GW_LINKS=%s\nEXPECTED_ZONE_LINKS=%s\nEXPECTED_NETWORKS=%s\n' "${GW_IFACES[*]}" "${ZONE_IFACES[*]}" "${NETWORKS[*]}"
} > "$TMP_STATE"
chmod 600 -- "$TMP_STATE"; chown root:root -- "$TMP_STATE"
if [[ -e "$STATE_FILE" ]] || ! mv -n -- "$TMP_STATE" "$STATE_FILE" || [[ -e "$TMP_STATE" ]]; then rm -f -- "$TMP_STATE"; die "state file appeared during deployment; refusing to overwrite: $STATE_FILE"; fi
for ns in "${ALL_NAMESPACES[@]}"; do
  ip netns add "$ns"
  CREATED_NAMESPACES+=("$ns")
  record_namespace_identity "$ns"
done
ip link add "${GW_LINKS[0]}" type veth peer name "${ZONE_LINKS[0]}"; CREATED_LINKS+=("${GW_LINKS[0]}" "${ZONE_LINKS[0]}")
ip link add "${GW_LINKS[1]}" type veth peer name "${ZONE_LINKS[1]}"; CREATED_LINKS+=("${GW_LINKS[1]}" "${ZONE_LINKS[1]}")
ip link add "${GW_LINKS[2]}" type veth peer name "${ZONE_LINKS[2]}"; CREATED_LINKS+=("${GW_LINKS[2]}" "${ZONE_LINKS[2]}")
ip link set "${GW_LINKS[0]}" netns "$GW_NS"; ip link set "${ZONE_LINKS[0]}" netns employee-ns
ip link set "${GW_LINKS[1]}" netns "$GW_NS"; ip link set "${ZONE_LINKS[1]}" netns app-ns
ip link set "${GW_LINKS[2]}" netns "$GW_NS"; ip link set "${ZONE_LINKS[2]}" netns data-ns

ip -n "$GW_NS" link set lo up
ip -n "$GW_NS" link set "${GW_LINKS[0]}" name gw-emp up
ip -n "$GW_NS" link set "${GW_LINKS[1]}" name gw-app up
ip -n "$GW_NS" link set "${GW_LINKS[2]}" name gw-data up
ip -n "$GW_NS" addr add 10.200.10.1/30 dev gw-emp
ip -n "$GW_NS" addr add 10.200.20.1/30 dev gw-app
ip -n "$GW_NS" addr add 10.200.30.1/30 dev gw-data

ip netns exec employee-ns ip link set lo up
ip netns exec employee-ns ip link set "${ZONE_LINKS[0]}" name emp-gw up
ip netns exec employee-ns ip addr add 10.200.10.2/30 dev emp-gw
ip netns exec employee-ns ip route add 10.200.20.0/30 via 10.200.10.1 dev emp-gw
ip netns exec employee-ns ip route add 10.200.30.0/30 via 10.200.10.1 dev emp-gw
ip netns exec app-ns ip link set lo up
ip netns exec app-ns ip link set "${ZONE_LINKS[1]}" name app-gw up
ip netns exec app-ns ip addr add 10.200.20.2/30 dev app-gw
ip netns exec app-ns ip route add 10.200.10.0/30 via 10.200.20.1 dev app-gw
ip netns exec app-ns ip route add 10.200.30.0/30 via 10.200.20.1 dev app-gw
ip netns exec data-ns ip link set lo up
ip netns exec data-ns ip link set "${ZONE_LINKS[2]}" name data-gw up
ip netns exec data-ns ip addr add 10.200.30.2/30 dev data-gw
ip netns exec data-ns ip route add 10.200.10.0/30 via 10.200.30.1 dev data-gw
ip netns exec data-ns ip route add 10.200.20.0/30 via 10.200.30.1 dev data-gw

# This sysctl is scoped to zt-gw-ns; the default namespace is not touched.
ip netns exec "$GW_NS" sysctl -q -w net.ipv4.ip_forward=1

TMP_STATE="$(mktemp --tmpdir="$STATE_DIR" .state.tmp.XXXXXX)"
{
  printf 'STATE_VERSION=1\nOWNER=zero-trust-network-security-lab\nTOKEN=%s\n' "$token"
  printf 'GW_NS=%s\n' "$GW_NS"
  printf 'PHASE=ACTIVE\nPID=%s\n' "$$"
  for ns in "${ALL_NAMESPACES[@]}"; do
    if ! identity="$(namespace_identity "$ns")"; then
      rm -f -- "$TMP_STATE"
      die "namespace identity acquisition failed before ACTIVE commit: $ns"
    fi
    valid_identity "$identity" || { rm -f -- "$TMP_STATE"; die "invalid namespace identity before ACTIVE commit: $ns"; }
    printf 'NS_%s_INODE=%s\n' "${ns//-/_}" "$identity"
  done
  printf 'EXPECTED_GW_LINKS=%s\n' "${GW_IFACES[*]}"
  printf 'EXPECTED_ZONE_LINKS=%s\n' "${ZONE_IFACES[*]}"
  printf 'EXPECTED_NETWORKS=%s\n' "${NETWORKS[*]}"
  printf 'IPV4_FORWARDING=1\n'
  printf 'CREATED_UTC=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$TMP_STATE"
chmod 600 -- "$TMP_STATE"
chown root:root -- "$TMP_STATE"
if [[ "$(awk -F= '$1 == "OWNER" {print $2; exit}' "$STATE_FILE")" != zero-trust-network-security-lab || "$(awk -F= '$1 == "TOKEN" {print $2; exit}' "$STATE_FILE")" != "$token" || "$(awk -F= '$1 == "PHASE" {print $2; exit}' "$STATE_FILE")" != CREATING ]]; then
  rm -f -- "$TMP_STATE"
  die "state ownership or phase changed; refusing ACTIVE commit: $STATE_FILE"
fi
mv -f -- "$TMP_STATE" "$STATE_FILE"


trap - ERR INT TERM EXIT
DEPLOY_SUCCESS=1
printf 'V0.3 topology created and recorded in %s.\n' "$STATE_FILE"
printf 'No NAT, external route, or formal firewall policy configured.\n'
