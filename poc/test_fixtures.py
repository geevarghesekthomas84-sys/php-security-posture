import unittest
from pathlib import Path

from php2shell_guard import INDICATORS


class FixtureTests(unittest.TestCase):
    def test_synthetic_log_contains_defensive_indicators(self):
        path = Path(__file__).parents[1] / "tests" / "fixtures" / "php2shell-sample.log"
        text = path.read_text(encoding="utf-8")
        matches = sum(bool(pattern.search(text)) for pattern, _ in INDICATORS)
        self.assertGreaterEqual(matches, 3)


if __name__ == "__main__":
    unittest.main()
