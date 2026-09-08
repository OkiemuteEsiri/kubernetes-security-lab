# Threat Model

## Protected Assets

- workload isolation
- node integrity
- Kubernetes API identity tokens
- application configuration and data
- container image integrity
- compute availability

## Trust Boundaries

- container to host
- workload to Kubernetes API
- namespace to namespace
- CI/CD pipeline to cluster admission
- image registry to runtime

## Threat Scenarios

| Scenario | Security concern | ATT&CK context | Primary control |
|---|---|---|---|
| Privileged workload | Container compromise has increased host impact | T1611 Escape to Host | prohibit privileged mode |
| Host namespace sharing | Workload gains visibility into host networking/process context | T1613 Container and Resource Discovery | disable host namespaces |
| Excessive workload identity | Unneeded API tokens increase credential exposure | T1528 Steal Application Access Token | disable unnecessary token automount |
| Mutable image reference | Deployment content can change without manifest change | supply-chain integrity | pin versions/digests |
| Root/privilege escalation | Compromise has greater local impact | T1611 defensive context | non-root + no privilege escalation |
| Missing limits | Resource abuse can affect availability | impact/DoS | CPU and memory limits |

## Assumptions

This model covers configuration-level preventive controls only. It does not claim to assess runtime vulnerabilities, kernel defects, malicious images, cloud IAM, secrets stored outside the workload manifest, or network behavior.

## Validation Objective

A hardened test workload should produce no findings under the implemented policy set, while deliberately insecure synthetic configuration should generate deterministic findings and fail the deployment gate.
