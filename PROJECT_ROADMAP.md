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

## V0.8 - Research analysis and reproducibility review

- Analyze results against the research questions.
- Review scripts, documentation, evidence naming, cleanup, and repeatability.
- Mark all unmeasured claims as limitations or future work.

## V0.9 - Release candidate

- Run a clean end-to-end trial in the selected Linux environment.
- Validate that the repository contains no secrets, host-wide commands, or unverified success claims.
- Prepare a reproducibility checklist and final report draft.

## V1.0 - Research release

- Publish the documented topology, tests, evidence index, results, limitations, and runtime decision.
- Confirm that no VM image installation, host network modification, attack activity, or Git commit is performed as part of this documentation phase.
