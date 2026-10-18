# Experiment Plan

This plan separates baseline behavior, segmentation behavior, and performance measurement. All experiments are to run only after the runtime capability and cleanup procedure have been validated.

## Experiment 0: runtime and safety pre-check

Record the Linux distribution/kernel, namespace and veth support, firewall tool availability, required privileges, available memory, and the exact lab-owned interface/rule inventory. Confirm that no command targets the Windows host network or default firewall. Create a cleanup checklist before creating any namespace.

## Experiment 1: baseline before segmentation

Objective: establish behavior without the intended zero-trust policy while retaining the same namespace topology where possible.

Record:

- namespace and interface inventory;
- routes and listeners per namespace;
- approved test-service reachability;
- employee-to-data and application-to-data reachability;
- connection setup time and failed-connection behavior;
- baseline CPU, memory, and test duration.

The baseline is a measurement condition, not a claim that unrestricted access is acceptable.

## Experiment 2: segmentation implementation

Objective: apply default-deny forwarding and explicit least-privilege rules in the isolated gateway and service namespaces.

Positive tests must show only documented flows succeed. Negative tests must cover employee-to-data, application-to-unapproved-data-port, wrong protocol, wrong destination port, and a route/interface path that is not in the allow matrix. Test established and new connections separately where relevant.

For each case, save the test input, expected result, observed result, relevant rule identifier/counter, timestamp, and cleanup status.

## Experiment 3: regression and rule-change validation

Change one policy item at a time, rerun the affected positive and negative tests, and verify that unrelated flows do not change. Reset only lab-owned state using the documented cleanup procedure. Do not use destructive host-wide reset commands.

## Experiment 4: performance evaluation

Compare baseline and segmented conditions using repeated, fixed-size connection tests. Candidate metrics are:

- allowed-flow success rate and blocked-flow success rate;
- median and percentile connection latency;
- throughput for a small controlled payload;
- CPU and memory usage of the gateway/test processes;
- rule evaluation overhead, if measurable;
- test-run duration and evidence size;
- cleanup completeness and repeatability across runs.

Use multiple repetitions, record environment details, and report variance. Resource results are measurements for this lab, not universal Linux performance claims.

## Acceptance criteria for the first implementation

The implementation is ready for research runs only when the topology can be created and removed without host changes, the documented allow flow succeeds, documented forbidden flows fail, repeated runs produce consistent results, and evidence identifies the policy and test that produced each result.
