"""Static defensive analyzer for synthetic Kubernetes workload manifests."""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from src.policies import policies

SEVERITY_WEIGHT = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 10}


def _pod_spec(document: Dict[str, Any]) -> Dict[str, Any]:
    spec = document.get("spec") or {}
    if document.get("kind") in {"Deployment", "DaemonSet", "StatefulSet", "Job"}:
        return ((spec.get("template") or {}).get("spec") or {})
    return spec


def analyze_manifest(document: Dict[str, Any]) -> Dict[str, Any]:
    pod_spec = _pod_spec(document)
    findings: List[Dict[str, Any]] = []

    if pod_spec.get("hostNetwork") is True:
        findings.append({
            "control_id": "K8S-009",
            "severity": "HIGH",
            "component": "pod",
            "message": "Pod uses the host network namespace",
            "remediation": "Set hostNetwork to false unless explicitly required and risk accepted.",
        })
    if pod_spec.get("hostPID") is True or pod_spec.get("hostIPC") is True:
        findings.append({
            "control_id": "K8S-010",
            "severity": "HIGH",
            "component": "pod",
            "message": "Pod uses a host process or IPC namespace",
            "remediation": "Disable hostPID/hostIPC unless explicitly justified.",
        })
    if pod_spec.get("automountServiceAccountToken") is not False:
        findings.append({
            "control_id": "K8S-011",
            "severity": "MEDIUM",
            "component": "pod",
            "message": "Service-account token automount is enabled or unspecified",
            "remediation": "Set automountServiceAccountToken to false for workloads that do not need Kubernetes API access.",
        })

    for container in pod_spec.get("containers") or []:
        name = container.get("name", "unnamed-container")
        for policy in policies():
            if policy.check(container):
                findings.append({
                    "control_id": policy.control_id,
                    "severity": policy.severity,
                    "component": name,
                    "message": policy.title,
                    "impact": policy.description,
                    "remediation": policy.remediation,
                })

    risk_score = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)
    return {
        "resource": (document.get("metadata") or {}).get("name", "unnamed-resource"),
        "kind": document.get("kind", "Unknown"),
        "findings": findings,
        "finding_count": len(findings),
        "risk_score": risk_score,
        "deployment_gate": "FAIL" if any(f["severity"] in {"CRITICAL", "HIGH"} for f in findings) else "PASS",
    }


def analyze_file(path: str) -> Dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return analyze_manifest(document)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python -m src.analyzer <manifest.json>")
        return 2
    result = analyze_file(sys.argv[1])
    print(json.dumps(result, indent=2))
    return 1 if result["deployment_gate"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
