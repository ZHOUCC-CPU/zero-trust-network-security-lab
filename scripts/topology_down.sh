#!/usr/bin/env bash
set -Eeuo pipefail

readonly STATE_DIR="/var/lib/ztlab-v03"
readonly STATE_FILE="$STATE_DIR/state"
readonly LOCK_FILE="/var/lock/ztlab-v03.lock"
readonly GW_NS="zt-gw-ns"
readonly ZONE_NAMES=(employee-ns app-ns data-ns)
readonly ALL_NAMESPACES=("$GW_NS" "${ZONE_NAMES[@]}")
readonly GW_IFACES=(gw-emp gw-app gw-data)
readonly ZONE_IFACES=(emp-gw app-gw data-gw)
DRY_RUN=0
ACTION_RUNNING=0

usage() { printf 'Usage: %s [--dry-run]\n' "$0"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
ns_exists() { ip netns list | awk '{print $1}' | grep -Fxq "$1"; }
read_state() {
  [[ -d "$STATE_DIR" ]] || die "state directory is missing: $STATE_DIR; ownership is not provable"
  [[ "$(stat -c '%u:%a' -- "$STATE_DIR" 2>/dev/null)" == '0:700' ]] || die 'state directory must be root-owned with mode 700'
  [[ -f "$STATE_FILE" ]] || die "state marker is missing: $STATE_FILE; ownership is not provable"
  [[ "$(stat -c '%u:%a' -- "$STATE_FILE" 2>/dev/null)" == '0:600' ]] || die 'state marker must be root-owned with mode 600'
  get_state() { awk -F= -v wanted="$1" '$1 == wanted { print substr($0, index($0, "=") + 1); exit }' "$STATE_FILE"; }
  STATE_VERSION="$(get_state STATE_VERSION)"
  OWNER="$(get_state OWNER)"
  TOKEN="$(get_state TOKEN)"
  CREATED_UTC="$(get_state CREATED_UTC)"
  PHASE="$(get_state PHASE)"
  [[ ${STATE_VERSION:-} == 1 ]] || die 'unsupported state marker version'
  [[ ${OWNER:-} == zero-trust-network-security-lab ]] || die 'state owner marker does not match this project'
  [[ -n ${TOKEN:-} && -n ${CREATED_UTC:-} ]] || die 'state marker is incomplete'
  [[ ${PHASE:-} == ACTIVE || ${PHASE:-} == CREATING || ${PHASE:-} == CLEANING || ${PHASE:-} == FAILED ]] || die "unsupported state phase: ${PHASE:-empty}"
  for ns in "${ALL_NAMESPACES[@]}"; do
    state_key="NS_${ns//-/_}_INODE"
    printf -v "$state_key" '%s' "$(get_state "$state_key")"
  done
}
verify_namespace() {
  local ns=$1 key=${1//-/_} expected state_key
  if ! ns_exists "$ns"; then
    [[ ${PHASE:-} == CREATING || ${PHASE:-} == CLEANING || ${PHASE:-} == FAILED ]] || die "owned namespace is missing before cleanup began: $ns"
    printf 'INFO: namespace absent; treating it as not-created or already cleaned: %s\n' "$ns" >&2
    return 0
  fi
  state_key="NS_${key}_INODE"
  expected=${!state_key-}
  [[ -n "$expected" ]] || die "state has no inode for namespace: $ns"
  [[ "$(stat -Lc '%d:%i' -- "/var/run/netns/$ns" 2>/dev/null)" == "$expected" ]] || die "namespace identity mismatch: $ns"
  [[ -z "$(ip netns pids "$ns" 2>/dev/null)" ]] || die "namespace has running processes: $ns"
}

verify_iface() {
    local ns=$1 iface=$2

    # Namespace 不存在的情况已由 verify_namespace 检查
    if ! ns_exists "$ns"; then
        return 0
    fi

    # 检查预期网络接口是否存在
    if ! ip -n "$ns" link show dev "$iface" >/dev/null 2>&1; then

        # 部分创建或部分清理时，接口允许尚未存在
        if [[ "$PHASE" == CREATING ||
              "$PHASE" == CLEANING ||
              "$PHASE" == FAILED ]]; then

            printf 'INFO: interface absent during %s: %s in %s\n' \
                "$PHASE" "$iface" "$ns" >&2
            return 0
        fi

        die "expected interface missing: $iface in $ns"
    fi

    # 已存在的接口必须是 veth 类型
    if ! ip -n "$ns" -d link show dev "$iface" 2>/dev/null | grep -Fq 'veth'; then
        die "unexpected interface type: $iface in $ns"
    fi
}

set_phase() {
  local phase=$1 tmp
  tmp="$(mktemp --tmpdir="$STATE_DIR" .state.phase.XXXXXX)"
  awk -F= -v phase="$phase" '{ if ($1 == "PHASE") print "PHASE=" phase; else print }' "$STATE_FILE" > "$tmp"
  chmod 600 -- "$tmp"; chown root:root -- "$tmp"; mv -f -- "$tmp" "$STATE_FILE"
}
show_plan() {
  printf 'DRY-RUN: ownership marker: %s\n' "$STATE_FILE"
  printf 'DRY-RUN: would remove only verified namespaces: %s\n' "${ALL_NAMESPACES[*]}"
  printf 'DRY-RUN: would remove namespace interfaces: %s / %s\n' "${GW_IFACES[*]}" "${ZONE_IFACES[*]}"
  printf 'DRY-RUN: no unrelated namespace, interface, route, or firewall resource is eligible.\n'
}

cleanup() {
    local rc=$?

    # 防止 EXIT trap 重复执行
    trap - EXIT

    # 正常退出不需要执行失败处理
    if (( rc == 0 )); then
        return 0
    fi

    set +e

    printf 'CLEANUP-FAIL: operation exited with code %s\n' \
        "$rc" >&2

    # 清理失败时保留状态文件，标记为 FAILED
    if [[ -f "$STATE_FILE" ]]; then
        if ! set_phase FAILED; then
            printf 'ERROR: failed to update state to FAILED\n' >&2
        fi
    else
        printf 'ERROR: state file is missing\n' >&2
    fi

    # 只报告残留，不自动删除未经重新验证的资源
    local ns
    for ns in "${ALL_NAMESPACES[@]}"; do
        if ns_exists "$ns"; then
            printf 'RESIDUAL: namespace %s remains\n' \
                "$ns" >&2
        fi
    done

    printf 'Cleanup incomplete; state retained for investigation.\n' >&2

    return "$rc"
}


while [[ $# -gt 0 ]]; do case "$1" in --dry-run) DRY_RUN=1;; -h|--help) usage; exit 0;; *) die "unknown option: $1";; esac; shift; done
[[ ${EUID} -eq 0 ]] || die 'root privileges are required inside Linux'
for cmd in ip awk grep stat flock mktemp chmod chown mv; do command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"; done
exec 9>"$LOCK_FILE"
flock -n 9 || die 'another V0.3 operation is already running'
read_state


# Step 1: Verify namespace identities before cleanup
for ns in "${ALL_NAMESPACES[@]}"; do
    verify_namespace "$ns"
done

# Step 2: Verify expected interfaces
verify_iface "$GW_NS" gw-emp
verify_iface "$GW_NS" gw-app
verify_iface "$GW_NS" gw-data
verify_iface employee-ns emp-gw
verify_iface app-ns app-gw
verify_iface data-ns data-gw

# Step 3: Dry-run must exit BEFORE any deletion
if [[ $DRY_RUN -eq 1 ]]; then
    show_plan
    exit 0
fi

# Step 4: Mark cleanup as started
set_phase CLEANING
trap cleanup EXIT

# Step 5: Reverify each namespace immediately before deletion
for ns in "${ALL_NAMESPACES[@]}"; do
    if ns_exists "$ns"; then
        verify_namespace "$ns"
        ip netns del "$ns"
    fi
done

# Step 6: Confirm all project namespaces are absent
for ns in "${ALL_NAMESPACES[@]}"; do
    if ns_exists "$ns"; then
        die "namespace remains after cleanup: $ns"
    fi
done

# Step 7: Remove state only after successful cleanup
rm -f -- "$STATE_FILE"

printf 'Cleanup completed; verified project namespaces are absent.\n'

trap - EXIT
