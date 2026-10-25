# Project Roadmap

## V0.1 - Scope and safety baseline

- Update project documentation from the former monitoring-lab description.
- Define the namespace topology, threat model, resource budget, allow-flow matrix, and host-safety rules.
- Identify required evidence and a reversible cleanup procedure.

## V0.2 - Runtime capability validation

- Evaluate WSL2 Ubuntu and one Ubuntu Server VM as candidates.
- Measure, rather than assume, namespace, veth, routing, firewall, privilege, persistence, and cleanup support.
- Record the selected runtime and unresolved limitations.

## V0.3 - Minimal topology prototype

- Create and remove the four planned namespaces and veth links.
- Add only lab-owned addresses and routes.
- Verify inventory and cleanup without implementing the final policy.

## V0.4 - Policy enforcement prototype

- Implement default deny and the smallest documented allow flows.
- Capture rule identifiers/counters and verify no host firewall changes.

## V0.5 - Automated verification

- Implement repeatable Python positive, negative, regression, and cleanup tests.
- Produce machine-readable results and human-readable evidence summaries.

## V0.6 - Baseline and segmentation experiments

- Run the baseline and segmented conditions with fixed test inputs.
- Repeat tests and document false allows, false denies, and operational failures.

## V0.7 - Performance and resource assessment

- Measure CPU, memory, latency, throughput, setup/teardown time, and evidence size.
- Compare results with the stated resource budget and record uncertainty.

## V0.8 - Security audit and reproducibility (completed)

- Completed 18/18 real traffic audit scenarios across three rounds.
- Captured nftables rule counters before and after each scenario.
- Recorded behavior evidence, JSON/CSV results and SHA-256 manifests.
- Independently validated the audit evidence and normal cleanup.
- Abnormal-interruption recovery is not fully established.

Evidence: [V0.8 Experiment Report](reports/V0.8_EXPERIMENT_REPORT.md).

Git commit: `cb7c124` (24 October 2026).

## V0.9 - Release candidate (locally validated)

- Implement independent read-only resource integrity checks.
- Verify project namespace, host interface and state-file absence.
- Run negative security regression tests.
- Review privileged execution and cleanup safety.
- Update README, roadmap and reproducibility documentation.
- Complete end-to-end release validation.
- Review repository contents for secrets and unsupported claims.
- Prepare final acceptance evidence and local Git commit.

Local acceptance results: 18/18 live scenarios, 3/3 round-level
counter checks, 15/15 evidence hashes and 10/10 offline regression
tests passed. Normal cleanup and resource integrity checks passed.

These findings do not establish complete fault recovery,
independent cross-host reproduction or production readiness.

## V1.0 - Research release

- Publish the documented topology, tests, evidence index, results, limitations, and runtime decision.
- Confirm that no VM image installation, host network modification, attack activity, or Git commit is performed as part of this documentation phase.
