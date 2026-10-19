import unittest
from sentinel.crypto import calculate_entropy, evaluate_password, identify_hash
from sentinel.scanner import scan_port
from sentinel.auditor import audit_url

class TestCyberSecSentinel(unittest.TestCase):
    def test_password_entropy(self):
        self.assertEqual(calculate_entropy(""), 0.0)
        res = evaluate_password("CorrectHorseBatteryStaple!2026")
        self.assertEqual(res["strength"], "Very Strong")
        self.assertGreater(res["entropy_bits"], 80)

    def test_hash_identification(self):
        self.assertEqual(identify_hash("d41d8cd98f00b204e9800998ecf8427e"), "MD5 / NTLM")
        self.assertEqual(identify_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709"), "SHA-1")
        self.assertEqual(identify_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "SHA-256")

    def test_audit_url_structure(self):
        res = audit_url("https://github.com")
        self.assertIn("grade", res)
        self.assertIn("present_headers", res)
        self.assertIn("missing_headers", res)

if __name__ == "__main__":
    unittest.main()
