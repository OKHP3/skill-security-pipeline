import unittest
from unittest.mock import patch

from scripts.check_technology_versions import npm_row, status, version


class ReleaseComparisonTests(unittest.TestCase):
    def test_numeric_comparison_does_not_sort_ten_before_nine(self):
        self.assertEqual(status("8.9.0", "8.10.0"), "update available")
        self.assertEqual(status("8.10.0", "8.9.0"), "ahead of upstream stable")

    def test_prereleases_and_floating_versions_are_not_exact_stable_pins(self):
        for value in ("3.14.0rc1", "v8.4.0-beta.1", "3.13", "latest"):
            with self.assertRaises(ValueError):
                version(value)
        self.assertEqual(status("3.13", "3.14.7"), "review floating or unknown version")

    def test_upstream_failure_stays_unknown(self):
        with patch("scripts.check_technology_versions.fetch", side_effect=TimeoutError):
            row = npm_row(("vite", {"current": "8.3.0"}))
        self.assertEqual(row["latest"], "unknown")
        self.assertIn("lookup failed", row["status"])

    def test_prerelease_latest_tag_is_not_accepted(self):
        with patch("scripts.check_technology_versions.fetch", return_value='{"version":"9.0.0-beta.1"}'):
            row = npm_row(("vite", {"current": "8.3.0"}))
        self.assertEqual(row["latest"], "unknown")


if __name__ == "__main__":
    unittest.main()
