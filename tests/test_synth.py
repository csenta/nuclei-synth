"""
Unit and integration tests for NucleiSynth.
"""

import os
import unittest
from parser import parse_raw_http, generate_heuristic_template
from validator import validate_template


class TestNucleiSynth(unittest.TestCase):

    def setUp(self):
        self.sample_advisory = """
        CVE-2024-4577: PHP CGI Argument Injection
        Severity: Critical

        POST /test.php?%ADd+allow_url_include%3d1 HTTP/1.1
        Host: target.local
        Content-Type: application/x-www-form-urlencoded

        <?php echo "test_nuclei_marker"; ?>

        Expected Response:
        HTTP/1.1 200 OK

        test_nuclei_marker
        """

    def test_parse_raw_http(self):
        parsed = parse_raw_http(self.sample_advisory)
        self.assertEqual(parsed["method"], "POST")
        self.assertIn("/test.php", parsed["path"])
        self.assertEqual(parsed["match_status"], 200)
        self.assertIn("application/x-www-form-urlencoded", parsed["headers"].get("Content-Type", ""))

    def test_heuristic_template_generation_and_validation(self):
        template_yaml = generate_heuristic_template(self.sample_advisory)
        self.assertIn("cve-2024-4577", template_yaml)
        self.assertIn("http:", template_yaml)

        # Validate with validator (including local Nuclei engine)
        is_valid, err_msg = validate_template(template_yaml)
        self.assertTrue(is_valid, f"Template failed validation: {err_msg}")

    def test_invalid_template_rejection(self):
        invalid_yaml = "id: missing-info\nhttp:\n  - method: GET"
        is_valid, err_msg = validate_template(invalid_yaml)
        self.assertFalse(is_valid)
        self.assertIn("info", err_msg)


if __name__ == "__main__":
    unittest.main()
