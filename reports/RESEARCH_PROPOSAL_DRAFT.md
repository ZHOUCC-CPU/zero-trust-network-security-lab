# Research Proposal Draft

**Document context:** This document preserves the original research questions, proposed methods, and metrics. The execution status below has been updated using evidence through the locally validated V0.9 release (`fb6bbd0`).

## Research Questions

1. Can one resource-constrained Linux environment provide repeatable network segmentation with namespaces, veth links, and Linux firewall policy?
2. Does a default-deny, least-privilege policy reliably permit documented employee-to-application access while blocking unauthorized cross-zone access?
3. What CPU, memory, latency, throughput, and operational costs are introduced by the isolated policy gateway and automated verification?
4. Which limitations arise when the same design is run in WSL2 Ubuntu compared with one Ubuntu Server virtual machine?

## Methodology

The following methodology records the original research plan. Actual execution, validated results, and uncompleted work are distinguished in the current-status section below.

Build a controlled topology containing employee, application, and sensitive-data namespaces connected through a dedicated policy namespace. Define the allow-flow matrix before deployment. Measure a baseline, apply the policy, execute positive and negative tests, and repeat the tests after controlled rule changes. A Python harness will produce structured results and preserve command/output evidence. Every run will record runtime details, policy version, test inputs, outcomes, and cleanup status.

WSL2 Ubuntu and a single Ubuntu Server VM will be evaluated as candidate runtimes through documented capability checks. The study will not assume namespace, veth, firewall, privilege, persistence, or host-isolation behavior until it is experimentally confirmed.

## Metrics

- policy correctness: true allowed-flow rate and true blocked-flow rate;
- false-allow and false-deny counts;
- connection latency and controlled-payload throughput;
- CPU, memory, and storage consumption;
- setup, teardown, and test execution time;
- repeatability across runs;
- evidence completeness and cleanup success;
- runtime capability differences between the two candidate environments.

## Limitations

The topology is a small synthetic model, not a production enterprise network. It does not model identity providers, endpoint posture, encrypted service identities, high availability, large-scale policy distribution, or a full SIEM. Results depend on the host, kernel, privileges, firewall implementation, and runtime mode. WSL2 and VM behavior may differ, and both require measurement. The project does not authorize testing outside the lab or changing the Windows host network and firewall.

## Current status

The project progressed beyond the original proposal.
The V0.3–V0.9 reports document the implemented
WSL2 namespace topology, gateway nftables policy,
automated network tests, controlled comparison,
bounded performance assessment, security audit,
and normal-cleanup validation.

The project reached the locally validated V0.9
release at Git commit `fb6bbd0`.

| Research question | Evidence-based status |
|---|---|
| RQ1: Linux feasibility and repeatability | Supported within the tested WSL2 Ubuntu environment; four namespaces, routing, regression tests, and normal cleanup were demonstrated. |
| RQ2: Least-privilege forwarding effectiveness | Supported within six defined network scenarios; V0.6 recorded 36/36 condition-specific outcomes across baseline and segmented testing. |
| RQ3: Operational and performance costs | Partially addressed through bounded V0.7 measurements of TCP timing, throughput, system-wide resources, and individual deployment/cleanup durations. |
| RQ4: WSL2 versus Ubuntu Server VM | Not fully answered; equivalent cross-runtime experimental evidence has not been established. |

The main verified V0.6 segmented results were
12/12 expected denials and 6/6 expected allows,
with zero observed false allows or false denies
within the defined test matrix.

V0.8 retained 18 individual scenario audit records
with corresponding before-and-after firewall counter
snapshots. V0.9 completed 18/18 scenario executions,
three round-level counter comparisons, and normal
resource cleanup.

These results demonstrate controlled network
microsegmentation, not complete Zero Trust
Architecture implementation or production readiness.

The original V0.2 feasibility record contains
user-provided terminal observations and must not
be described as independent reproduction.

Comprehensive abnormal-crash recovery, identity
authentication, device posture, complete IPv6
coverage, and equivalent VM comparison remain
outside the demonstrated results.

## Research evidence references

- [V0.3 topology report](V0.3_EXPERIMENT_REPORT.md)
- [V0.4 firewall report](V0.4_EXPERIMENT_REPORT.md)
- [V0.5 regression report](V0.5_EXPERIMENT_REPORT.md)
- [V0.6 controlled comparison](V0.6_EXPERIMENT_REPORT.md)
- [V0.7 performance assessment](V0.7_EXPERIMENT_REPORT.md)
- [V0.8 security audit](V0.8_EXPERIMENT_REPORT.md)
- [V0.9 end-to-end validation](V0.9_EXPERIMENT_REPORT.md)
- [V1.0 research evidence index](V1.0_RESEARCH_EVIDENCE_INDEX.md)

This status update is documentation only. No new
network experiments or VM comparisons are claimed.
