import unittest

from src.policies import policies


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy_map = {p.control_id: p for p in policies()}

    def test_privileged_container_detected(self):
        container = {"securityContext": {"privileged": True}}
        self.assertTrue(self.policy_map["K8S-001"].check(container))

    def test_non_root_hardened_container_not_flagged(self):
        container = {"securityContext": {"runAsNonRoot": True}}
        self.assertFalse(self.policy_map["K8S-003"].check(container))

    def test_latest_image_flagged(self):
        container = {"image": "example/service:latest"}
        self.assertTrue(self.policy_map["K8S-007"].check(container))

    def test_complete_resource_limits_not_flagged(self):
        container = {"resources": {"limits": {"cpu": "1", "memory": "256Mi"}}}
        self.assertFalse(self.policy_map["K8S-008"].check(container))


if __name__ == "__main__":
    unittest.main()
