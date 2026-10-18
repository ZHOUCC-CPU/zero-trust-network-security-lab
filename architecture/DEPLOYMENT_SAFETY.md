# V0.3 Deployment Safety Procedure

## Source and runtime locations

The reviewed source repository remains on the Windows DrvFS mount:

```text
/mnt/d/Cybersecurity-Portfolio/zero-trust-network-security-lab
```

The V0.3 runtime state must not be stored on that mount. The scripts use the Ubuntu-native path:

```text
/var/lib/ztlab-v03/state
```

The state directory must be root-owned with mode `700`; the state file must be root-owned with mode `600`. The deployment script creates this directory only when the user actually starts deployment. This documentation phase does not create it.

## Reviewed-script staging workflow

Before deployment, the operator should copy only the reviewed scripts to a root-controlled native filesystem directory, for example:

```bash
install -d -o root -g root -m 700 /root/ztlab-v03-reviewed
install -o root -g root -m 700 scripts/topology_up.sh /root/ztlab-v03-reviewed/topology_up.sh
install -o root -g root -m 700 scripts/topology_down.sh /root/ztlab-v03-reviewed/topology_down.sh
install -o root -g root -m 700 scripts/check_topology.sh /root/ztlab-v03-reviewed/check_topology.sh
```

The commands above are a future operator procedure, not commands executed in V0.3 preparation. Before running anything, compare the staged files with the reviewed repository files using a hash or a careful diff, then obtain explicit user approval.

## State integrity

The state writer uses a temporary file in the native state directory, applies restrictive permissions and root ownership, and performs a no-overwrite move into `state`. It refuses to overwrite an existing state file. State parsing uses an allow-listed key/value parser and never uses `source` or `eval`.

Namespace identity is recorded and checked with `stat -Lc '%d:%i' /var/run/netns/<name>`. The same method is used by creation and cleanup; an empty result is an error. Lifecycle phases are recorded as `CREATING`, `ACTIVE`, `CLEANING`, or `FAILED`. A native `flock` lock prevents concurrent deployment and cleanup. If cleanup is partial, the state remains and is marked `FAILED`; a subsequent cleanup must revalidate the remaining resources before removing them.

`tests/test_control_logic.sh` contains logic-only checks for state validity, missing and empty identities, identity mismatch, locking guards, signal rollback source guards, partial-failure state retention, and namespace PASS/FAIL source logic. These tests do not create namespaces or interfaces.

## Boundaries

The deployment procedure must not modify the Windows network, Ubuntu default namespace routes or firewall, unrelated namespaces, unrelated interfaces, or global nftables/iptables state. V0.3 does not install a firewall policy, NAT, or external route. V0.4 will implement and test access-control rules separately.
