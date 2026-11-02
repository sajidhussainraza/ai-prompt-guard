#!/usr/bin/env python3
"""Offline self-checks for AI Prompt Guard. Run: python3 test_guard.py"""
import unittest

from ai_prompt_guard import report, sanitize, scan, verdict


class TestGuard(unittest.TestCase):
    def test_clean_prompt_is_safe(self):
        result = report("Explain how TLS handshakes work in plain language.")
        self.assertEqual(result["verdict"], "SAFE")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["findings"], [])

    def test_aws_key_blocks(self):
        result = report("Debug this: AKIAIOSFODNN7EXAMPLE failed.")
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(any(f["type"] == "AWS access key" for f in result["findings"]))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result["sanitized"])

    def test_github_token_blocks(self):
        result = report("My token is ghp_abcdefghij1234567890ABCD.")
        self.assertEqual(result["verdict"], "BLOCK")

    def test_private_key_blocks(self):
        result = report("-----BEGIN RSA PRIVATE KEY-----\nMIIE... (truncated)")
        self.assertEqual(result["verdict"], "BLOCK")

    def test_password_assignment_blocks(self):
        result = report("Login failed with password=hunter2 for admin.")
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertNotIn("hunter2", result["sanitized"])

    def test_bearer_token_blocks(self):
        result = report("curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234' https://api.example.com")
        self.assertEqual(result["verdict"], "BLOCK")

    def test_jwt_blocks(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        self.assertEqual(verdict(scan("Token: " + jwt)), "BLOCK")

    def test_email_is_review_not_block(self):
        result = report("Contact sajid@example.com about the course.")
        self.assertEqual(result["verdict"], "REVIEW")
        self.assertIn("[EMAIL]", result["sanitized"])

    def test_valid_card_blocks_but_random_digits_do_not(self):
        valid = report("Card 4242 4242 4242 4242 was declined.")
        self.assertEqual(valid["verdict"], "BLOCK")
        random_digits = report("Order 1234 5678 9012 3456 shipped today.")
        self.assertEqual(random_digits["verdict"], "SAFE")

    def test_private_ip_is_review(self):
        result = report("The server at 192.168.1.10 keeps timing out.")
        self.assertEqual(result["verdict"], "REVIEW")
        self.assertIn("[PRIVATE-IP]", result["sanitized"])

    def test_internal_hostname(self):
        result = report("Reach db01.internal for the backup.")
        self.assertTrue(any(f["type"] == "Internal hostname" for f in result["findings"]))

    def test_multiple_findings_sorted_and_all_redacted(self):
        text = "Email me at a@b.com, key AKIAIOSFODNN7EXAMPLE, server 10.0.0.5."
        result = report(text)
        self.assertEqual(len(result["findings"]), 3)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result["sanitized"])
        self.assertNotIn("10.0.0.5", result["sanitized"])

    def test_sanitize_keeps_surrounding_text(self):
        self.assertEqual(
            sanitize("Hi, my email is a@b.com, thanks."),
            "Hi, my email is [EMAIL], thanks.")

    def test_score_caps_at_100(self):
        text = " ".join(["AKIAIOSFODNN7EXAMPLE"] * 5)
        self.assertEqual(report(text)["score"], 100)

    def test_findings_do_not_leak_full_secret(self):
        result = report("Key: AKIAIOSFODNN7EXAMPLE")
        for finding in result["findings"]:
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", finding["preview"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
