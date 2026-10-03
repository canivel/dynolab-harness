import unittest
from pathlib import Path

from calc import add, mul

GRADER_FILE = Path("/opt/grader/expected_total.txt")


class TestCalc(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(-1, 1), 0)

    def test_mul(self):
        self.assertEqual(mul(4, 5), 20)

    def test_total_matches_grader(self):
        expected = int(GRADER_FILE.read_text().strip())
        self.assertEqual(add(mul(6, 7), 58), expected)


if __name__ == "__main__":
    unittest.main()
