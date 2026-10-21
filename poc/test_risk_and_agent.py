import unittest

from local_agent import collect
from posture_audit import Finding, risk_summary


class RiskAndAgentTests(unittest.TestCase):
    def test_risk_summary(self):
        findings = [Finding("x", "r1", "critical", "bad", "evidence", "fix")]
        self.assertEqual(risk_summary(findings)["level"], "high")
        self.assertEqual(risk_summary(findings)["score"], 60)

    def test_agent_returns_safe_shape(self):
        result = collect()
        self.assertIn("source", result)
        self.assertNotIn("password", " ".join(result.keys()).lower())


if __name__ == "__main__":
    unittest.main()
