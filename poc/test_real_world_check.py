import unittest

from real_world_check import check


class RealWorldCheckTests(unittest.TestCase):
    def test_unreachable_target_is_safe_result(self):
        result = check("http://127.0.0.1:1/health.php", 0.2, None, False)
        self.assertEqual(result["status"], "unreachable")


if __name__ == "__main__":
    unittest.main()
