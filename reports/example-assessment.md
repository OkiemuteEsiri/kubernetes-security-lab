# Example Assessment — Synthetic API Workload

## Executive Summary

The deliberately insecure synthetic API workload fails the preventive deployment gate because it contains multiple high-impact isolation and privilege weaknesses. The assessment is generated from static lab configuration and is not a claim about any real environment.

## Highest-Priority Findings

| Control | Severity | Finding | Recommended action |
|---|---|---|---|
| K8S-001 | Critical | Privileged container | Disable privileged mode |
| K8S-009 | High | Host network namespace | Disable hostNetwork |
| K8S-002 | High | Privilege escalation allowed | Set allowPrivilegeEscalation=false |
| K8S-003 | High | Non-root execution not enforced | Set runAsNonRoot=true |
| K8S-006 | High | Added Linux capability | Drop ALL and justify any required capability |
| K8S-011 | Medium | Service-account token automount | Disable when Kubernetes API access is not required |

## Risk Interpretation

The combination of privileged execution, host namespace exposure, root-capable execution, and additional capabilities materially weakens the container isolation boundary. In a real engineering workflow, these issues would be prioritized before release because compromise of the workload could have greater impact on the hosting environment.

## Remediation Validation

The paired hardened fixture demonstrates the target state used by the test suite: non-root execution, no privilege escalation, `RuntimeDefault` seccomp, read-only root filesystem, dropped capabilities, pinned image tag, resource limits, disabled host namespaces, and disabled service-account token automount.

## Decision

**Synthetic insecure workload:** FAIL deployment gate.

**Synthetic hardened workload:** expected to PASS the implemented static policy baseline when evaluated by the test suite.
