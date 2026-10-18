#!/usr/bin/env bash
set -Eeuo pipefail

# Logic-only tests. This file never calls ip, ip netns, sysctl, nft, or a
# project deployment/cleanup script. It tests state parsing and source guards.
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
pass=0; fail=0
ok() { printf 'PASS|%s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL|%s\n' "$1" >&2; fail=$((fail + 1)); }
assert() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }

state_value() { awk -F= -v wanted="$2" '$1 == wanted { print substr($0, index($0, "=") + 1); exit }' "$1"; }
valid_state() {
  local file=$1
  [[ -f "$file" ]] || return 1
  [[ "$(state_value "$file" STATE_VERSION)" == 1 ]] || return 1
  [[ "$(state_value "$file" OWNER)" == zero-trust-network-security-lab ]] || return 1
  [[ -n "$(state_value "$file" TOKEN)" ]] || return 1
  [[ -n "$(state_value "$file" NS_zt_gw_ns_INODE)" ]] || return 1
}
identity_from_stat_output() { local value=$1; [[ -n "$value" && "$value" != *$'\n'* ]] && printf '%s\n' "$value"; }
not_valid_state() { ! valid_state "$1"; }
not_grep() { local pattern=$1; shift; ! grep -Eq "$pattern" "$@"; }
write_phase_atomic() {
  local file=$1 token=$2 phase=$3 tmp
  tmp="$(mktemp "$TMP/state.XXXXXX")"
  printf 'OWNER=zero-trust-network-security-lab\nTOKEN=%s\nPHASE=%s\n' "$token" "$phase" > "$tmp"
  if [[ -e "$file" ]]; then rm -f "$tmp"; return 2; fi
  mv -n "$tmp" "$file" && [[ ! -e "$tmp" ]]
}
commit_active() {
  local file=$1 token=$2 tmp
  [[ "$(state_value "$file" OWNER)" == zero-trust-network-security-lab ]] || return 1
  [[ "$(state_value "$file" TOKEN)" == "$token" ]] || return 1
  [[ "$(state_value "$file" PHASE)" == CREATING ]] || return 1
  tmp="$(mktemp "$TMP/active.XXXXXX")"
  printf 'OWNER=zero-trust-network-security-lab\nTOKEN=%s\nPHASE=ACTIVE\n' "$token" > "$tmp"
  mv -f "$tmp" "$file"
}
partial_cleanup_model() {
  local state=$1 remaining=$2 expected=$3 actual=$4
  [[ -f "$state" ]] || return 2
  [[ "$expected" == "$actual" ]] || return 3
  if [[ "$remaining" == keep-ns ]]; then
    sed -i 's/^PHASE=.*/PHASE=FAILED/' "$state"
    return 1
  fi
  rm -f "$state"
}
nonzero_case() { return 7; }
not_commit_active() { ! commit_active "$@"; }
not_write_state() { ! write_phase_atomic "$@"; }
expect_nonzero() { ! nonzero_case; }
expect_identity_reject() { ! partial_cleanup_model "$@"; }

cat > "$TMP/state" <<'EOF'
STATE_VERSION=1
OWNER=zero-trust-network-security-lab
TOKEN=test-token
PHASE=ACTIVE
NS_zt_gw_ns_INODE=42:9001
EOF
assert valid-state valid_state "$TMP/state"
assert missing-state not_valid_state "$TMP/missing"
sed 's/42:9001//' "$TMP/state" > "$TMP/empty"
assert empty-identity not_valid_state "$TMP/empty"
sed 's/42:9001/99:1/' "$TMP/state" > "$TMP/mismatch"
assert identity-mismatch test "$(state_value "$TMP/mismatch" NS_zt_gw_ns_INODE)" = 99:1
assert stat-identity identity_from_stat_output 42:9001

assert source-forbidden not_grep 'source[[:space:]]+"?\$.*STATE' "$ROOT/scripts/topology_down.sh"
assert lock-present grep -Eq 'flock -n 9' "$ROOT/scripts/topology_up.sh"
assert lock-present-cleanup grep -Eq 'flock -n 9' "$ROOT/scripts/topology_down.sh"
assert signal-rollback grep -Eq 'on_signal.*rollback' "$ROOT/scripts/topology_up.sh"
assert failure-phase grep -Eq 'set_phase FAILED' "$ROOT/scripts/topology_down.sh"
assert no-global-firewall not_grep 'nft[[:space:]]+flush|iptables[[:space:]]+(-F|--flush)' "$ROOT/scripts"/*
assert namespace-pass-argument grep -Eq 'ns_exists "\$ns"' "$ROOT/scripts/check_topology.sh"
assert namespace-fail-output grep -Eq 'fail namespace "missing:' "$ROOT/scripts/check_topology.sh"
assert no-deployment-call not_grep 'bash[[:space:]]+scripts/topology_(up|down)\.sh' "$ROOT/tests"/*

rm -f "$TMP/phase-state"
assert creating-state write_phase_atomic "$TMP/phase-state" token-a CREATING
assert active-transition commit_active "$TMP/phase-state" token-a
assert active-record test "$(state_value "$TMP/phase-state" PHASE)" = ACTIVE
assert token-conflict not_commit_active "$TMP/phase-state" token-b
assert atomic-no-overwrite not_write_state "$TMP/phase-state" token-c CREATING

exec 8>"$TMP/lock"
flock -n 8
assert lock-conflict bash -c 'exec 7>"$1"; ! flock -n 7' bash "$TMP/lock"
flock -u 8
cat > "$TMP/cleanup-state" <<'EOF'
PHASE=CLEANING
TOKEN=cleanup-token
EOF
assert partial-cleanup-returns-nonzero expect_identity_reject "$TMP/cleanup-state" keep-ns cleanup-token cleanup-token
assert partial-cleanup-state-retained test -f "$TMP/cleanup-state"
assert partial-cleanup-marked-failed test "$(state_value "$TMP/cleanup-state" PHASE)" = FAILED
assert partial-cleanup-identity-mismatch expect_identity_reject "$TMP/cleanup-state" keep-ns cleanup-token other-token
assert remaining-cleanup-after-auth partial_cleanup_model "$TMP/cleanup-state" absent cleanup-token cleanup-token
assert all-cleanup-removes-state test ! -e "$TMP/cleanup-state"
assert failure-returns-nonzero expect_nonzero

printf 'SUMMARY|logic_tests|passed=%d failed=%d\n' "$pass" "$fail"
(( fail == 0 ))
