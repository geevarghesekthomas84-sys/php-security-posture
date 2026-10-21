import unittest

from assess_fleet import assess, render_sarif


class FleetAssessmentTests(unittest.TestCase):
    def test_unreachable_is_unknown(self):
        result = assess("http://127.0.0.1:1/health.php")
        self.assertEqual(result["status"], "unknown")

    def test_sarif_contains_non_passing_target(self):
        report = render_sarif([{"target": "example", "status": "upgrade_required", "guidance": "upgrade"}])
        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(report["runs"][0]["results"][0]["level"], "error")


if __name__ == "__main__":
    unittest.main()
