# Architecture

## Objective

Provide a transparent, dependency-light example of preventive Kubernetes configuration analysis suitable for CI/CD security gates and security-engineering review.

## Data Flow

1. A Kubernetes-style JSON manifest is loaded.
2. The workload pod specification is normalized for Deployment, DaemonSet, StatefulSet, Job, or Pod style resources.
3. Pod-level controls evaluate host namespaces and service-account token exposure.
4. Container-level policies evaluate privilege, user context, capabilities, seccomp, filesystem posture, image tagging, and resources.
5. Findings are normalized into control ID, severity, component, impact, and remediation.
6. A deterministic risk score is calculated from finding severities.
7. Critical/high findings fail the deployment gate.

## Design Principles

- **Explainable:** policies are readable Python objects rather than opaque models.
- **Safe:** input is static synthetic configuration; the engine does not connect to clusters.
- **Testable:** hardened and insecure fixtures produce deterministic expectations.
- **Extensible:** controls can be added to the policy catalogue without changing the analyzer workflow.
- **Remediation-oriented:** every finding contains a practical corrective action.

## Production Evolution

A production implementation would normally add schema validation, YAML parsing, SARIF output, admission-controller integration, policy exception governance, image provenance checks, RBAC/NetworkPolicy analysis, audit logging, and organization-specific risk thresholds.
