import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_domains as checker


class DomainNormalizationTests(unittest.TestCase):
    def test_bare_names_get_default_tld(self):
        self.assertEqual(checker.canonical_domain("  MiXeD  ", "com"), "mixed.com")

    def test_domain_keeps_suffix_and_normalizes_idn(self):
        self.assertEqual(checker.canonical_domain("bücher.de", "com"), "xn--bcher-kva.de")

    def test_rejects_urls_and_invalid_labels(self):
        for value in ("https://example.com", "bad/name.com", "-bad.com", "bad..com"):
            with self.subTest(value=value):
                self.assertIsNone(checker.canonical_domain(value, "com"))

    def test_com_uses_verisign_and_other_tlds_use_rdap_org(self):
        self.assertTrue(checker.rdap_url("example.com").startswith("https://rdap.verisign.com/com/v1/domain/"))
        self.assertEqual(checker.rdap_url("example.de"), "https://rdap.org/domain/example.de")


class LookupTests(unittest.TestCase):
    def test_200_is_taken(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def getcode(self):
                return 200

            def read(self, _size):
                return b"{}"

        with patch.object(checker, "urlopen", return_value=Response()):
            row = checker.check_domain("taken.com", checker.RequestPacer(0), 1, 0)
        self.assertEqual(row["status"], "taken")
        self.assertEqual(row["http_status"], "200")

    def test_404_is_available(self):
        err = HTTPError("https://example.com", 404, "Not Found", {}, io.BytesIO())
        with patch.object(checker, "urlopen", side_effect=err):
            row = checker.check_domain("free.com", checker.RequestPacer(0), 1, 0)
        self.assertEqual(row["status"], "available")
        self.assertEqual(row["http_status"], "404")

    def test_network_error_is_unknown_not_available(self):
        with patch.object(checker, "urlopen", side_effect=OSError("network unavailable")):
            row = checker.check_domain("uncertain.com", checker.RequestPacer(0), 1, 0)
        self.assertEqual(row["status"], "unknown")
        self.assertIn("network unavailable", row["detail"])


if __name__ == "__main__":
    unittest.main()
