# Kubernetes Security Engineering Lab

A recruiter-facing defensive security engineering project for assessing Kubernetes workload posture, validating deployment security controls, and producing remediation-ready findings from manifest data.

> **Scope:** synthetic lab manifests only. No production clusters, credentials, exploit payloads, or confidential data are used.

## Problem Statement

Kubernetes environments concentrate identity, network, runtime, image, and configuration risk. Security teams need repeatable controls that identify insecure workload configuration before deployment and translate findings into actionable remediation.

This project implements a lightweight policy engine that inspects Kubernetes-style workload manifests for common security weaknesses such as privileged containers, host namespace access, missing resource limits, risky capabilities, mutable image tags, absent non-root enforcement, missing seccomp controls, and weak service-account handling.

## Architecture

```text
Synthetic manifests
        |
        v
Manifest loader
        |
        v
Policy engine -----> Policy catalogue
        |
        v
Risk scoring / severity normalization
        |
        +----> JSON/console findings
        +----> remediation guidance
        +----> validation workflow
```

## Repository Structure

```text
.
├── src/
│   ├── analyzer.py
│   ├── policies.py
│   └── reporting.py
├── tests/
│   ├── test_analyzer.py
│   └── test_policies.py
├── data/
│   ├── secure-deployment.json
│   └── insecure-deployment.json
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   └── remediation-validation.md
├── reports/
│   └── example-assessment.md
└── .github/workflows/tests.yml
```

## Security Controls Implemented

The current policy catalogue evaluates:

- privileged container execution
- host PID / IPC / network namespace exposure
- root execution and missing `runAsNonRoot`
- privilege escalation
- Linux capability additions
- missing seccomp profile
- writable root filesystem
- mutable or unspecified image tags
- missing CPU/memory limits
- service-account token automount

## Risk Model

Findings are normalized into four severity levels:

| Severity | Typical meaning | Action |
|---|---|---|
| Critical | Immediate node/workload boundary risk | Block deployment |
| High | Material privilege or isolation weakness | Remediate before release |
| Medium | Defense-in-depth gap | Track to remediation SLA |
| Low | Hardening opportunity | Improve baseline |

The project intentionally emphasizes explainability. Every policy produces a control ID, affected component, impact statement, remediation, and validation guidance.

## Example Usage

```bash
python -m src.analyzer data/insecure-deployment.json
```

Example result shape:

```json
{
  "control_id": "K8S-001",
  "severity": "CRITICAL",
  "component": "api",
  "message": "Container runs in privileged mode",
  "remediation": "Set securityContext.privileged to false."
}
```

## Testing

```bash
python -m unittest discover -s tests -v
```

Tests validate both vulnerable and hardened synthetic manifests and verify severity, policy matching, and expected remediation behavior.

## Threat Mapping

Relevant defensive ATT&CK context includes:

- **T1610 — Deploy Container**
- **T1611 — Escape to Host**
- **T1613 — Container and Resource Discovery**
- **T1552.007 — Unsecured Credentials: Container API**
- **T1528 — Steal Application Access Token**

ATT&CK references are used for defensive context and coverage planning, not exploitation guidance.

## Remediation Strategy

1. Remove privileged execution and unnecessary host namespace access.
2. Enforce non-root execution and disable privilege escalation.
3. Drop unnecessary Linux capabilities.
4. Apply `RuntimeDefault` seccomp profiles.
5. Prefer read-only root filesystems where operationally possible.
6. Pin immutable image versions or digests.
7. Define CPU and memory requests/limits.
8. Disable service-account token automount unless required.
9. Re-run policy validation after changes.
10. Promote only when critical/high policy failures are closed or formally accepted.

## CI/CD

A GitHub Actions workflow runs the Python unit-test suite on pushes and pull requests. This demonstrates a basic preventive DevSecOps gate while keeping the repository self-contained and dependency-light.

## Skills Demonstrated

- Kubernetes security engineering
- container hardening
- policy-as-code concepts
- Python security automation
- secure configuration analysis
- DevSecOps controls
- threat modelling
- remediation validation
- unit testing
- security reporting

## Limitations

This lab performs static analysis of synthetic manifest data. It does not claim runtime cluster visibility, admission-controller enforcement, cloud-provider posture coverage, image vulnerability scanning, or production validation.

## Roadmap

- add NetworkPolicy validation
- add Pod Security Standards profile mapping
- add RBAC graph analysis
- add image provenance/SBOM metadata checks
- add SARIF export
- add policy exceptions with expiry controls
- add risk trend reporting

## Ethical Use

Use only with systems and configurations you own or are explicitly authorized to assess. The repository is designed for defensive engineering, education, and portfolio demonstration.