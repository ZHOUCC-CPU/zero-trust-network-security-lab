# Research Proposal Draft

## Research Questions

1. Can one resource-constrained Linux environment provide repeatable network segmentation with namespaces, veth links, and Linux firewall policy?
2. Does a default-deny, least-privilege policy reliably permit documented employee-to-application access while blocking unauthorized cross-zone access?
3. What CPU, memory, latency, throughput, and operational costs are introduced by the isolated policy gateway and automated verification?
4. Which limitations arise when the same design is run in WSL2 Ubuntu compared with one Ubuntu Server virtual machine?

## Methodology

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

The repository contains the project structure and design documents. Namespace deployment, firewall implementation, automated tests, measurements, and empirical runtime comparison are planned work and must not be described as completed until evidence exists.
