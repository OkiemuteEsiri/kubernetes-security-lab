"""Human-readable reporting helpers for Kubernetes security assessments."""

from collections import Counter
from typing import Any, Dict


def summarize(result: Dict[str, Any]) -> str:
    counts = Counter(f["severity"] for f in result.get("findings", []))
    lines = [
        f"Resource: {result.get('kind')} / {result.get('resource')}",
        f"Deployment gate: {result.get('deployment_gate')}",
        f"Risk score: {result.get('risk_score')}",
        f"Findings: {result.get('finding_count')}",
        "Severity summary: " + ", ".join(f"{k}={counts.get(k, 0)}" for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    ]
    for finding in result.get("findings", []):
        lines.append(
            f"- [{finding['severity']}] {finding['control_id']} {finding['component']}: {finding['message']}"
        )
    return "\n".join(lines)
