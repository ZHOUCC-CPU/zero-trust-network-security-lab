#!/usr/bin/env bash
set -Eeuo pipefail

GW="zt-gw-ns"
STATE="/var/lib/ztlab-v03/state"
LOCK="/var/lock/ztlab-v03.lock"
POLICY="/root/ztlab-v03-reviewed/v04_gateway_filter.nft"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || die "Root required"

for cmd in ip nft flock stat awk; do
    command -v "$cmd" >/dev/null || die "Missing: $cmd"
done

exec 9>"$LOCK"
flock -n 9 || die "Another topology operation is running"

[[ -f "$STATE" ]] || die "V0.3 is not deployed"
[[ "$(stat -c '%u:%a' "$STATE")" == "0:600" ]] || die "Invalid state permissions"

read_state() {
    awk -F= -v key="$1" '$1==key {print $2; exit}' "$STATE"
}

[[ "$(read_state OWNER)" == "zero-trust-network-security-lab" ]] || die "Invalid owner"
[[ "$(read_state PHASE)" == "ACTIVE" ]] || die "Topology is not ACTIVE"

expected="$(read_state NS_zt_gw_ns_INODE)"
[[ "$expected" =~ ^[0-9]+:[0-9]+$ ]] || die "Invalid namespace identity"

actual="$(stat -Lc '%d:%i' "/var/run/netns/$GW")" || die "Gateway missing"
[[ "$actual" == "$expected" ]] || die "Gateway identity mismatch"

for iface in gw-emp gw-app gw-data; do
    ip -n "$GW" link show dev "$iface" >/dev/null || die "Missing interface: $iface"
done

[[ -f "$POLICY" ]] || die "Reviewed policy file missing"
[[ "$(stat -c '%u:%a' "$POLICY")" == "0:600" ]] || die "Invalid policy permissions"

if ip netns exec "$GW" nft list tables |
    awk '$1=="table" && $2=="inet" && $3=="ztlab_v04" {found=1} END {exit !found}'; then
    die "V0.4 table already exists; refusing overwrite"
fi

ip netns exec "$GW" nft -c -f "$POLICY" || die "Policy check failed"
ip netns exec "$GW" nft -f "$POLICY" || die "Policy loading failed"

echo "PASS: V0.4 firewall loaded into $GW"
