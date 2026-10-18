# Zero Trust Network Security Lab

**An evidence-backed Linux network microsegmentation lab using network namespaces, veth, routing, nftables, and automated policy tests.**

**Project status:** V0.4 core experiment completed and documented (18 October 2026). V0.5–V1.0 research and hardening remain in progress or planned.

> **Scope:** This is a controlled, isolated network **microsegmentation** prototype inspired by Zero Trust principles. It is **not** a complete Zero Trust Architecture: it does not implement identity-based authentication, device posture verification, continuous authorization, or enterprise policy orchestration.

## Overview

The lab models three network zones and a dedicated routing/policy enforcement gateway inside WSL2 Ubuntu. The project compares connectivity before filtering (V0.3) with access under a stateful, default-deny nftables forwarding policy (V0.4). Evidence is retained as timestamped terminal outputs and English experiment reports.

The project is designed for a resource-constrained personal computer (approximately 16 GB of system RAM), with a lightweight WSL2 Ubuntu environment rather than a full multi-VM deployment.

## Architecture

```text
                       employee-ns
                       10.200.10.2/30
                            |
                    emp-gw <-> gw-emp
                            |
                     +--------------+
                     |   zt-gw-ns   |
                     | IPv4 routing |
                     | nftables     |
                     +--------------+
                       /          \
               gw-app /            \ gw-data
                     /              \
                 app-gw            data-gw
                   |                  |
                app-ns             data-ns
             10.200.20.2/30    10.200.30.2/30
```

| Zone | Namespace | Zone address | Gateway address |
| --- | --- | --- | --- |
| Employee | `employee-ns` | `10.200.10.2/30` | `10.200.10.1/30` |
| Application | `app-ns` | `10.200.20.2/30` | `10.200.20.1/30` |
| Data | `data-ns` | `10.200.30.2/30` | `10.200.30.1/30` |
| Policy gateway | `zt-gw-ns` | Three gateway-side veth endpoints | Internal IPv4 forwarding |

The three zone links use veth pairs and explicit internal static routes. The experiment does not configure NAT, external routes, or host-wide firewall rules. V0.4 policy enforcement is limited to the **forwarding hook in the gateway namespace**; it does not restrict all traffic originating in, or destined for, an individual namespace.

## Technology and environment

- Windows 11 host with WSL2 Ubuntu 24.04
- Linux network namespaces, virtual Ethernet (veth), `iproute2`, IPv4 routing
- `nftables` 1.0.9: stateful, default-deny forwarding policy
- Python 3.12.3: temporary HTTP test endpoints and TCP checks
- Bash: topology lifecycle and automated regression testing
- Root-controlled Ubuntu-native staging for privileged scripts and the policy file

## V0.4 policy matrix

The enforced nftables table is `inet ztlab_v04`, with `forward` **policy `drop`**.

| Source | Destination | Protocol/port | Expected outcome |
| --- | --- | --- | --- |
| Employee | Application | TCP 8080 | Allow new connections |
| Application | Data | TCP 5432 | Allow new connections |
| Employee | Data | ICMP | Drop |
| Employee | Data | TCP 5432 | Drop |
| Employee | Application | TCP 8081 | Drop |
| Data | Application | TCP 8080 | Drop |
| Any other unmatched forwarded traffic | Other zone | Unspecified | Drop by default |

Established/related connection packets are accepted for return traffic. Rule counters track accepted and dropped traffic. TCP 5432 tests used a temporary **HTTP server listening on port 5432**, not a PostgreSQL deployment; they verify network reachability and access control, not database functionality.

## Verified experimental results

### V0.3 — Topology prototype

- Four namespaces and three veth pairs were deployed in the live WSL2 environment.
- All **36 topology checks passed**, including address, interface, route, forwarding, reachability, and state ownership checks.
- Normal cleanup succeeded; a subsequent independent check found **0 failures** among the specified namespace, interface-name, and state-file checks.

Evidence:

- [`evidence/V0.3_topology_validation_20261018T131943Z.txt`](evidence/V0.3_topology_validation_20261018T131943Z.txt)
- [`evidence/V0.3_cleanup_validation_20261018T132350Z.txt`](evidence/V0.3_cleanup_validation_20261018T132350Z.txt)
- [`reports/V0.3_EXPERIMENT_REPORT.md`](reports/V0.3_EXPERIMENT_REPORT.md)

### V0.4 — Policy enforcement and regression

- The gateway namespace accepted the `nftables` rules with the default-deny forwarding policy active.
- **Six manual access tests passed**: two explicitly allowed TCP paths and four representative denied paths.
- **Six automated regression scenarios passed** with **0 failures**.
- The post-test firewall snapshot recorded 1 new-connection packet matched by each allow rule, 22 established/related packets, and 12 packets matched by the final drop rule during the manual test sequence.
- The separate automated regression run reported positive-path allow-counter increments and denied-path drop-counter increments.
- Normal cleanup completed; subsequent verification reported **0 residual failures** for four project namespace names, six specified interface names, and the deployment state file.

Evidence:

- [`evidence/V0.4_firewall_snapshot_20261018T135546Z.txt`](evidence/V0.4_firewall_snapshot_20261018T135546Z.txt)
- [`evidence/V0.4_regression_20261018T144222Z.txt`](evidence/V0.4_regression_20261018T144222Z.txt)
- [`evidence/V0.4_cleanup_validation_20261018T144747Z.txt`](evidence/V0.4_cleanup_validation_20261018T144747Z.txt)
- [`reports/V0.4_EXPERIMENT_REPORT.md`](reports/V0.4_EXPERIMENT_REPORT.md)

These findings describe **specific observed test runs**. They do not establish complete coverage of unauthorized traffic, resistance to all bypass techniques, or generalizable performance results.

## Repository structure

```text
.
├── README.md
├── PROJECT_ROADMAP.md
├── .gitignore
├── architecture/
│   ├── ARCHITECTURE_DESIGN.md
│   └── DEPLOYMENT_SAFETY.md
├── deployment/
│   └── v04_gateway_filter.nft
├── experiments/
│   └── EXPERIMENT_PLAN.md
├── scripts/
│   ├── topology_up.sh
│   ├── topology_down.sh
│   ├── check_topology.sh
│   ├── load_v04_policy.sh
│   └── test_v04_firewall.sh
├── tests/
│   └── test_control_logic.sh
├── evidence/
└── reports/
    ├── RESEARCH_PROPOSAL_DRAFT.md
    ├── V0.3_EXPERIMENT_REPORT.md
    └── V0.4_EXPERIMENT_REPORT.md
```

## Safety and reproducibility

Privileged topology and firewall operations must be run only in an authorized test environment. The lab uses project-owned namespaces, and the policy is installed inside `zt-gw-ns` rather than the host network namespace.

**Important:** The working repository may reside on a Windows-mounted path (`/mnt/d/...`). Do **not** run privileged scripts directly from that mutable mount. Review and stage the scripts and nftables file on an Ubuntu-native root-owned directory first, following [`architecture/DEPLOYMENT_SAFETY.md`](architecture/DEPLOYMENT_SAFETY.md).

The tested lifecycle is:

1. Review and securely stage the topology scripts and policy.
2. Deploy V0.3 namespaces using the reviewed `topology_up.sh`.
3. Run `check_topology.sh` before enabling filtering (baseline connectivity checks).
4. Load the reviewed V0.4 policy using `load_v04_policy.sh`.
5. Run `test_v04_firewall.sh` and save structured output in `evidence/`.
6. Check for remaining namespace processes and perform `topology_down.sh --dry-run`.
7. Perform normal cleanup and independently verify resource absence.

The V0.3 connectivity checker expects inter-zone ICMP reachability and therefore is intended for the **pre-policy baseline**; after the V0.4 default-deny policy is applied, some of its ping checks will intentionally fail.

The repository includes simulated/control-logic tests under `tests/`; those are not substitutes for live network tests. Do not infer abnormal-interruption recovery or rollback safety from a successful normal teardown.

## Limitations and planned research

- No identity verification, device trust, continuous authorization, or application-level authentication is implemented.
- The policy primarily addresses IPv4 forwarding; IPv6 behavior, spoofed source addresses, host traffic, and namespace-local input/output policy require additional examination.
- Tests cover six representative cases rather than an exhaustive traffic matrix.
- Privileged script failure modes, concurrent operations, interruption handling, and rollback have not been fully exercised in live tests.
- No formal latency, throughput, CPU, memory, or statistical repeatability comparison has been completed.
- Results apply to the stated WSL2 environment and recorded runs; they are not a production deployment certification.

**Next milestones:** expand the test framework and machine-readable evidence (V0.5), conduct repeatable baseline-versus-segmented experiments (V0.6), measure resource/performance impact (V0.7), review research and reproducibility (V0.8), and prepare a validated release (V0.9–V1.0). See [`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md).

## Academic and portfolio purpose

This project documents practical network isolation, least-privilege rule design, stateful filtering, repeatable security tests, and evidence-based reporting for study and a cybersecurity/computer-science portfolio. Claims are deliberately limited to observed results and recorded experimental evidence.
