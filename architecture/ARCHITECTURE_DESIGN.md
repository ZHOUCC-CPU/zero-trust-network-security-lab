# Zero Trust Network Security Lab: Architecture Design

## Purpose and scope

This lab studies whether network namespaces, virtual Ethernet (veth) links, Linux firewall policy, and automated tests can provide a repeatable zero-trust segmentation experiment on one Linux system. The design is confined to dedicated experiment namespaces. It must not change the Windows host network, host firewall, routing table, or default firewall policy.

This document describes the planned architecture. It does not claim that the topology or controls have been deployed.

## V0.2 and V0.3 status

V0.2 runtime results were supplied by the user from terminal output and are recorded in `evidence/V0.2_RUNTIME_VALIDATION.md`; they have not been independently re-tested. V0.3 deployed a four-namespace topology with three veth pairs and three /30 subnets. All 36 topology validation checks passed. Normal cleanup was also verified. V0.3 configured internal routing without NAT, external egress, host firewall changes, or formal filtering rules.

V0.4 implemented stateful default-deny forwarding with nftables inside `zt-gw-ns`. The policy permits Employee-to-Application TCP 8080 and Application-to-Data TCP 5432. Six automated regression scenarios passed with zero failures. Final cleanup checks detected no residual failures among the specified resources.

The V0.3 scripts use `/var/lib/ztlab-v03/state` on the Ubuntu-native filesystem as the ownership record. The directory must be root-owned with mode `700`, and the state file root-owned with mode `600`. The marker stores a version, owner identifier, token, lifecycle phase, creation time, namespace identity references, expected interface groups, expected networks, and the gateway forwarding setting. Namespace identity is calculated consistently with `stat -Lc '%d:%i'` against the namespace bind mount; an empty or mismatched identity is an error. Cleanup refuses to proceed when the marker is absent or inconsistent, when a namespace identity does not match, when an expected interface is missing or misplaced, or when a namespace contains processes. Dry-run cleanup performs these checks and prints the deletion plan without modifying resources. This is a safety control, not a substitute for operator review.

Deployment and cleanup use a native `flock` lock. The state lifecycle is `CREATING`, `ACTIVE`, `CLEANING`, or `FAILED`. A failed cleanup retains the state and marks it `FAILED`; a later cleanup may treat already-absent resources as completed only after the prior cleanup phase and remaining resources have been revalidated. An `ACTIVE` state with a missing resource is treated as an ownership failure, not as permission to delete anything else.

The topology checker distinguishes topology reachability from access control. V0.3 expects the three zones to reach their gateway and, because no firewall policy is enabled yet, expects routed cross-zone reachability to be possible. These checks do not demonstrate authorization correctness; formal default-deny testing belongs to V0.4.

## Planned logical topology

```text
employee namespace (employee-ns)
        |
     veth pair
        |
policy/router namespace (zt-gw-ns)
        |---------------- veth ---------------- application namespace (app-ns)
        |
        `---------------- veth ---------------- sensitive-data namespace (data-ns)
```

The gateway namespace is the only planned transit point. Each application and data service is bound to its own namespace address. The employee namespace represents a client zone; it is not a trusted network merely because it is inside the lab.

Planned addressing uses documentation-only private ranges allocated inside the lab, for example `10.200.10.0/24` (employee), `10.200.20.0/24` (application), and `10.200.30.0/24` (sensitive data). The exact addresses, interface names, and firewall syntax remain implementation decisions for the deployment stage.

## Zero-trust policy model

- Default deny: forwarding and service access are denied unless a test explicitly enables an allow rule.
- Least privilege: permit only the required source namespace, destination namespace, protocol, destination port, and connection state.
- Explicit flows: employee-to-application may be allowed for the selected application service; employee-to-data is denied; application-to-data may be allowed only for a narrowly defined service flow.
- No implicit trust: namespace membership does not bypass policy, and return traffic is allowed only as established/related traffic where the experiment requires it.
- Auditability: policy changes and test results must be recorded with timestamps, rule identifiers, source/destination, protocol, expected result, and observed result.
- Containment: all interfaces, routes, firewall rules, listeners, and test traffic must stay within the experiment namespaces.

The allowed-flow matrix will be finalized before deployment. A negative test must demonstrate that an unapproved cross-zone flow is blocked, not merely that an approved flow succeeds.

## Components and responsibilities

| Component | Responsibility | Planned state |
|---|---|---|
| `employee-ns` | Simulated employee client | Planned |
| `app-ns` | Simulated internal application endpoint | Planned |
| `data-ns` | Simulated sensitive data endpoint | Planned |
| `zt-gw-ns` | Isolated routing and policy enforcement point | Planned |
| veth pairs | Point-to-point namespace connectivity | Planned |
| Linux firewall rules | Default-deny and explicit allow policy | Planned |
| Python test harness | Repeatable positive/negative checks and evidence | Planned |

## Resource budget

The target is one Linux environment and four lightweight namespaces. Namespaces do not require four virtual machines; their cost is expected to be primarily processes, kernel objects, sockets, and test services. Actual memory and CPU usage must be measured during validation rather than assumed.

| Resource | Budget/constraint | Measurement plan |
|---|---|---|
| Concurrent VMs | Zero required | Verify the selected host mode uses one Linux environment only |
| Namespaces | 4 planned | `ip netns list` and deployment inventory |
| RAM | Must fit within the user's approximately 5.54 GB free baseline | Record before/after and peak process usage |
| CPU | No always-on heavy service | Measure idle and test-run utilization |
| Storage | Small scripts, logs, and packet/test evidence | Record artifact sizes and retention policy |
| Host changes | None permitted | Review commands and post-test host-state checks |

## Threat model

### Assets

The sensitive-data service, application service availability, policy integrity, test evidence, and reproducibility of results are in scope.

### In-scope threats

- An employee-zone process attempts direct access to the data zone.
- An application-zone process reaches an unapproved data port.
- A newly created or misconfigured route bypasses the intended gateway policy.
- A firewall rule is broader than the documented allow flow.
- Return traffic or connection tracking creates an unintended access path.
- A test or cleanup procedure leaks processes, routes, or interfaces outside the lab.

### Out of scope

Attacking external systems, evading authorization, modifying the Windows host firewall, internet-scale threat emulation, and production security claims are out of scope.

### Security assumptions to validate

The selected Linux runtime must support network namespaces, veth, routing, and the chosen firewall tooling. WSL2 Ubuntu and a single Ubuntu Server VM are candidates, but support, privileges, persistence, and isolation must be tested in Phase 2. No candidate is treated as validated in this document.
