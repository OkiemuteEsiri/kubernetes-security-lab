"""Defensive Kubernetes manifest policy catalogue."""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class Policy:
    control_id: str
    title: str
    severity: str
    description: str
    remediation: str
    check: Callable[[Dict[str, Any]], bool]


def _security_context(container: Dict[str, Any]) -> Dict[str, Any]:
    return container.get("securityContext") or {}


def _resources(container: Dict[str, Any]) -> Dict[str, Any]:
    return container.get("resources") or {}


def policies() -> List[Policy]:
    return [
        Policy(
            "K8S-001",
            "Privileged container",
            "CRITICAL",
            "Privileged containers weaken workload-to-host isolation.",
            "Set securityContext.privileged to false and grant only required permissions.",
            lambda c: _security_context(c).get("privileged") is True,
        ),
        Policy(
            "K8S-002",
            "Privilege escalation allowed",
            "HIGH",
            "A process may gain more privileges than its parent process.",
            "Set securityContext.allowPrivilegeEscalation to false.",
            lambda c: _security_context(c).get("allowPrivilegeEscalation") is not False,
        ),
        Policy(
            "K8S-003",
            "Non-root execution not enforced",
            "HIGH",
            "Running as root increases impact if a container is compromised.",
            "Set securityContext.runAsNonRoot to true and use a non-root image user.",
            lambda c: _security_context(c).get("runAsNonRoot") is not True,
        ),
        Policy(
            "K8S-004",
            "Seccomp profile missing",
            "MEDIUM",
            "Missing seccomp controls increases available kernel syscall surface.",
            "Set securityContext.seccompProfile.type to RuntimeDefault or an approved profile.",
            lambda c: (_security_context(c).get("seccompProfile") or {}).get("type") not in {"RuntimeDefault", "Localhost"},
        ),
        Policy(
            "K8S-005",
            "Writable root filesystem",
            "MEDIUM",
            "Writable container filesystems increase persistence and tampering opportunities.",
            "Set securityContext.readOnlyRootFilesystem to true where operationally feasible.",
            lambda c: _security_context(c).get("readOnlyRootFilesystem") is not True,
        ),
        Policy(
            "K8S-006",
            "Added Linux capabilities",
            "HIGH",
            "Additional Linux capabilities can expand process privilege.",
            "Drop ALL capabilities and explicitly add only those justified by the workload.",
            lambda c: bool(((_security_context(c).get("capabilities") or {}).get("add") or [])),
        ),
        Policy(
            "K8S-007",
            "Mutable image tag",
            "MEDIUM",
            "Mutable image references weaken reproducibility and provenance assurance.",
            "Pin a version or digest and avoid latest or untagged images.",
            lambda c: ":latest" in c.get("image", "") or ":" not in c.get("image", ""),
        ),
        Policy(
            "K8S-008",
            "Resource limits missing",
            "MEDIUM",
            "Missing resource limits can increase denial-of-service impact and noisy-neighbour risk.",
            "Define CPU and memory limits appropriate to the workload.",
            lambda c: not {"cpu", "memory"}.issubset(((_resources(c).get("limits") or {}).keys())),
        ),
    ]
