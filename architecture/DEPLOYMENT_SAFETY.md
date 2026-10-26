# V0.3 Deployment Safety Procedure

## V1.0 safety interpretation

**Documentation only — not authorization to execute.**
This file preserves the original V0.3 deployment
procedure. The historical staging commands below
must not be copied and rerun against an existing
reviewed Root staging directory.

The `install` commands can overwrite existing
files, including independently reviewed scripts
already present under `/root/ztlab-v03-reviewed`.

Any future privileged reproduction requires
a separately authorized procedure, including:

- Review of exact repository and staged-file hashes.
- Verification of Root ownership and permissions.
- Confirmation of the approved nftables policy.
- Verification of project state and namespace identities.
- Inspection of project-owned interfaces and routes.
- Validation of the shared operation lock.
- A reviewed cleanup and failure-handling procedure.

A missing `/run/lock` file after WSL restart is
not permission to bypass synchronization guards.

The implemented V0.3 topology temporarily
created project veth endpoints in the default
Linux network namespace before moving them
into their experimental namespaces. Therefore,
zero interaction with that namespace is not
claimed. Persistent host-wide firewall or
external route modifications were not
intentionally part of the experiment.

V0.4 subsequently implemented stateful
default-deny forwarding through nftables
inside `zt-gw-ns`. This does not imply
host-wide filtering or identity-based
Zero Trust enforcement.

V0.9 was locally validated and committed
as `fb6bbd0`. V1.0 is a research
documentation release candidate, not a new deployment.

This documentation phase does not authorize
VM installation, network deployment, Root
staging changes, firewall modification,
attack activity, or Git publication.

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

The following commands are retained as historical V0.3 staging examples only. Do not execute them against an existing reviewed Root staging directory. A newly authorized staging procedure must separately verify exact file hashes, ownership, permissions, and operation-lock state before any privileged action:

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

The deployment procedure must not modify the Windows network, Ubuntu default namespace routes or firewall, unrelated namespaces, unrelated interfaces, or global nftables/iptables state. V0.3 does not install a firewall policy, NAT, or external route. At the V0.3 planning stage, V0.4 was expected to implement and test access-control rules separately.
