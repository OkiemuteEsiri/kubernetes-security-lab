# Remediation and Validation Workflow

## Triage

1. Confirm the finding applies to the intended workload specification.
2. Validate whether the control is required by an approved exception.
3. Prioritize Critical and High findings before release.
4. Assign remediation ownership to the workload team.

## Remediation Patterns

- **Privileged container:** set `privileged: false`; redesign the workload if host-level privileges are genuinely required.
- **Privilege escalation:** set `allowPrivilegeEscalation: false`.
- **Root execution:** set `runAsNonRoot: true` and use an image that supports a non-root UID.
- **Capabilities:** drop `ALL`; add only documented capabilities.
- **Seccomp:** use `RuntimeDefault` or an approved local profile.
- **Filesystem:** set `readOnlyRootFilesystem: true` where the application supports it.
- **Image provenance:** replace mutable `latest`/untagged references with versioned tags or digests.
- **Resource governance:** configure CPU and memory limits based on measured workload requirements.
- **Service-account token:** set `automountServiceAccountToken: false` unless API access is required.
- **Host namespaces:** disable host networking/PID/IPC unless formally justified.

## Validation

After remediation:

1. Re-run the analyzer against the changed manifest.
2. Confirm the original control ID is no longer returned.
3. Run the unit-test suite.
4. Confirm no new Critical/High findings were introduced.
5. Record evidence in the change or pull request.
6. Reassess time-limited exceptions before expiry.

## Acceptance Criteria

A workload is considered compliant with this lab baseline when:

- deployment gate returns `PASS`;
- there are no Critical or High findings;
- any remaining lower-severity findings are documented and tracked;
- the configuration change is reproducible in source control.
