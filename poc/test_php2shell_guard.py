import unittest

from php2shell_guard import parse_php_info, version


class GuardTests(unittest.TestCase):
    def test_parse_php_info(self):
        fields = parse_php_info("PHP Version => 8.2.35 => 8.2.35\nsession.upload_progress.enabled => Off => Off")
        self.assertEqual(fields["PHP Version"], "8.2.35")
        self.assertEqual(fields["session.upload_progress.enabled"], "Off")

    def test_version(self):
        self.assertEqual(version("PHP 8.5.12"), (8, 5, 12))


if __name__ == "__main__":
    unittest.main()
