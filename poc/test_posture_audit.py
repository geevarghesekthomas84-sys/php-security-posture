import unittest

from posture_audit import audit_fields, render, version_tuple


class PostureAuditTests(unittest.TestCase):
    def test_version_tuple(self):
        self.assertEqual(version_tuple("PHP 8.2.34"), (8, 2, 34))

    def test_old_build_is_critical(self):
        findings = audit_fields("lab", {"PHP_VERSION": "8.2.34", "UPLOAD_PROGRESS": "1", "PUBLIC_HEALTH_VERSION": "1"})
        self.assertEqual(findings[0].severity, "critical")
        self.assertTrue(any(item.rule_id == "PHP-UPLOAD-PROGRESS" for item in findings))

    def test_markdown_report(self):
        findings = audit_fields("lab", {"PHP_VERSION": "8.2.35", "UPLOAD_PROGRESS": "0", "PUBLIC_HEALTH_VERSION": "0"})
        self.assertIn("PHP-BASELINE-PASS", render(findings, "markdown"))


if __name__ == "__main__":
    unittest.main()
