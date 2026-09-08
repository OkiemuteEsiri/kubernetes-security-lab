import json
import unittest
from pathlib import Path

from src.analyzer import analyze_manifest


class AnalyzerTests(unittest.TestCase):
    def load(self, name):
        return json.loads(Path("data", name).read_text(encoding="utf-8"))

    def test_insecure_manifest_fails_gate(self):
        result = analyze_manifest(self.load("insecure-deployment.json"))
        self.assertEqual(result["deployment_gate"], "FAIL")
        self.assertGreater(result["finding_count"], 5)
        ids = {finding["control_id"] for finding in result["findings"]}
        self.assertIn("K8S-001", ids)
        self.assertIn("K8S-009", ids)
        self.assertIn("K8S-011", ids)

    def test_hardened_manifest_passes_gate(self):
        result = analyze_manifest(self.load("secure-deployment.json"))
        self.assertEqual(result["deployment_gate"], "PASS")
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
