# Zero Trust Network Security Lab: Architecture Design

## Purpose and scope

This lab studies whether network namespaces, virtual Ethernet (veth) links, Linux firewall policy, and automated tests can provide a repeatable zero-trust segmentation experiment on one Linux system. The design is confined to dedicated experiment namespaces. It must not change the Windows host network, host firewall, routing table, or default firewall policy.

This document originated as a design specification. The four-namespace topology and gateway forwarding policy were subsequently implemented and tested through V0.9. Historical V0.2 feasibility results retain their original evidence-provenance limitations.

## V0.2 and V0.3 status

V0.2 runtime results were supplied by the user from terminal output and are recorded in `evidence/V0.2_RUNTIME_VALIDATION.md`; they have not been independently re-tested. V0.3 deployed a four-namespace topology with three veth pairs and three /30 subnets. All 36 topology validation checks passed. Normal cleanup was also verified. V0.3 configured internal routing without NAT, external egress, host firewall changes, or formal filtering rules.

V0.4 implemented stateful default-deny forwarding with nftables inside `zt-gw-ns`. The policy permits Employee-to-Application TCP 8080 and Application-to-Data TCP 5432. Six automated regression scenarios passed with zero failures. Final cleanup checks detected no residual failures among the specified resources.

V0.5–V0.9 subsequently added repeatable network regression, baseline-versus-segmented comparison, bounded performance measurements, per-scenario firewall auditing, and end-to-end release validation. V0.9 completed 18/18 representative live scenario executions, three round-level counter comparisons, and successful normal resource cleanup. The V0.9 local release commit is `fb6bbd0`.

The V0.3 scripts use `/var/lib/ztlab-v03/state` on the Ubuntu-native filesystem as the ownership record. The directory must be root-owned with mode `700`, and the state file root-owned with mode `600`. The marker stores a version, owner identifier, token, lifecycle phase, creation time, namespace identity references, expected interface groups, expected networks, and the gateway forwarding setting. Namespace identity is calculated consistently with `stat -Lc '%d:%i'` against the namespace bind mount; an empty or mismatched identity is an error. Cleanup refuses to proceed when the marker is absent or inconsistent, when a namespace identity does not match, when an expected interface is missing or misplaced, or when a namespace contains processes. Dry-run cleanup performs these checks and prints the deletion plan without modifying resources. This is a safety control, not a substitute for operator review.

Deployment and cleanup use a native `flock` lock. The state lifecycle is `CREATING`, `ACTIVE`, `CLEANING`, or `FAILED`. A failed cleanup retains the state and marks it `FAILED`; a later cleanup may treat already-absent resources as completed only after the prior cleanup phase and remaining resources have been revalidated. An `ACTIVE` state with a missing resource is treated as an ownership failure, not as permission to delete anything else.

The topology checker distinguishes topology reachability from access control. V0.3 expects the three zones to reach their gateway and, because no firewall policy is enabled yet, expects routed cross-zone reachability to be possible. These checks do not demonstrate authorization correctness; formal default-deny testing belongs to V0.4.

## Implemented logical topology (V0.9 baseline)

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

The gateway namespace is the intended inter-zone transit point. Temporary application and data test listeners bind to their respective namespace addresses. The employee namespace represents a simulated client zone; namespace membership does not imply trust.

The implemented topology uses three internal point-to-point IPv4 subnets: `10.200.10.0/30` (Employee-Gateway), `10.200.20.0/30` (Application-Gateway), and `10.200.30.0/30` (Data-Gateway). The gateway endpoint uses `.1` and the zone endpoint uses `.2` within each subnet. The gateway forwarding policy is defined in `deployment/v04_gateway_filter.nft`.

## Zero-trust policy model

- Default deny: the nftables `forward` chain in `zt-gw-ns` denies routed traffic by default unless an explicit forwarding rule permits it. This does not establish namespace-local input/output filtering.
- Least privilege: permit only the required source namespace, destination namespace, protocol, destination port, and connection state.
- Explicit flows: employee-to-application may be allowed for the selected application service; employee-to-data is denied; application-to-data may be allowed only for a narrowly defined service flow.
- No implicit trust: namespace membership does not bypass policy, and return traffic is allowed only as established/related traffic where the experiment requires it.
- Auditability: policy changes and test results must be recorded with timestamps, rule identifiers, source/destination, protocol, expected result, and observed result.
- Containment: test forwarding, listeners, addresses and nftables enforcement are confined to the intended experimental namespaces. During deployment, project-owned veth interfaces are temporarily created in the default Linux network namespace before being moved into the lab namespaces. No host-wide firewall policy or external route is intentionally installed.

The implemented forwarding matrix allows Employee-to-Application TCP 8080 and Application-to-Data TCP 5432, together with established/related return traffic. Representative negative tests verify denied cross-zone flows using connection behavior and nftables counters. These tests do not establish coverage of every protocol, address or bypass scenario.

## Components and responsibilities

| Component | Responsibility | Verified implementation status |
|---|---|---|
| `employee-ns` | Simulated employee client | Implemented; V0.3 topology |
| `app-ns` | Simulated internal application endpoint | Implemented; V0.3 topology |
| `data-ns` | Simulated sensitive data endpoint | Implemented; V0.3 topology |
| `zt-gw-ns` | Isolated routing and policy enforcement point | Implemented; V0.3 topology and V0.4 policy |
| veth pairs | Point-to-point namespace connectivity | Implemented; three isolated links |
| Linux firewall rules | Default-deny and explicit allow policy | Implemented; V0.4 gateway policy |
| Python test harness | Repeatable positive/negative checks and evidence | Implemented; automated validation through V0.9 |

## Resource budget

The target is one Linux environment and four lightweight namespaces. Namespaces do not require four virtual machines; their cost is expected to be primarily processes, kernel objects, sockets, and test services. Actual memory and CPU usage must be measured during validation rather than assumed.

| Resource | Budget/constraint | Measurement plan |
|---|---|---|
| Concurrent VMs | Zero required | Verify the selected host mode uses one Linux environment only |
| Namespaces | 4 implemented | `ip netns list` and recorded deployment inventory |
| RAM | Must fit within the user's approximately 5.54 GB free baseline | Record before/after and peak process usage |
| CPU | No always-on heavy service | Measure idle and test-run utilization |
| Storage | Small scripts, logs, and packet/test evidence | Record artifact sizes and retention policy |
| Host changes | No persistent host-wide route or firewall changes; temporary project veth creation in the default Linux namespace | Review commands and post-test resource checks |

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

### Runtime validation and remaining assumptions

The recorded WSL2 Ubuntu experiments demonstrated namespace creation, veth connectivity, isolated routing, nftables forwarding policy, repeatable behavioral checks, and successful normal cleanup. The initial V0.2 feasibility results were user-provided terminal observations; subsequent versions retained additional experiment evidence. An equivalent Ubuntu Server VM comparison, comprehensive abnormal-crash recovery, IPv6 controls, anti-spoofing coverage, and production readiness have not been established. See `reports/V1.0_RESEARCH_EVIDENCE_INDEX.md` for evidence boundaries.
