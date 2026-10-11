"""Session / cookie / CSRF handling tests."""
from __future__ import annotations

import unittest

from ..session import SessionState, extract_csrf, parse_cookie_header


class TestParseCookieHeader(unittest.TestCase):
    def test_pairs(self):
        out = parse_cookie_header("a=1; b=2; c=hello world")
        self.assertEqual(out, {"a": "1", "b": "2", "c": "hello world"})

    def test_empty(self):
        self.assertEqual(parse_cookie_header(""), {})

    def test_garbage_ignored(self):
        out = parse_cookie_header("noequal; x=1")
        self.assertEqual(out, {"x": "1"})


class TestSessionState(unittest.TestCase):
    def test_headers_include_cookie_and_csrf(self):
        s = SessionState(cookie_header="sid=abc", csrf_token="tok123")
        h = s.headers()
        self.assertEqual(h["Cookie"], "sid=abc")
        self.assertEqual(h["X-CSRF-Token"], "tok123")

    def test_headers_without_csrf(self):
        s = SessionState(cookie_header="sid=abc")
        self.assertNotIn("X-CSRF-Token", s.headers())

    def test_authenticated_flag(self):
        self.assertTrue(SessionState(cookie_header="a=1").authenticated)
        self.assertFalse(SessionState().authenticated)

    def test_merge_cookies_adds_and_updates(self):
        s = SessionState(cookie_header="a=1")
        s.merge_cookies(["b=2; Path=/", "a=3; Path=/"])
        self.assertEqual(s.cookies(), {"a": "3", "b": "2"})
        self.assertEqual(sorted(s.seen_cookie_names), ["a", "b"])

    def test_merge_cookies_deletes_on_empty_value(self):
        s = SessionState(cookie_header="a=1; b=2")
        s.merge_cookies(["b=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"])
        self.assertEqual(s.cookies(), {"a": "1"})

    def test_merge_ignores_malformed(self):
        s = SessionState(cookie_header="a=1")
        s.merge_cookies(["garbage without equals", "123=x"])
        # names must start with a letter per our conservative filter
        self.assertIn("a", s.cookies())


class TestExtractCsrf(unittest.TestCase):
    def test_meta_name_before_content(self):
        html = '<meta name="csrf-token" content="abc123token">'
        self.assertEqual(extract_csrf(html), "abc123token")

    def test_meta_content_before_name(self):
        html = '<meta content="xyz789token" name="_csrf">'
        self.assertEqual(extract_csrf(html), "xyz789token")

    def test_embedded_json(self):
        html = '<script>window.config = {"csrfToken": "jsonTok42abc"};</script>'
        self.assertEqual(extract_csrf(html), "jsonTok42abc")

    def test_xsrf_cookie_wins(self):
        html = '<meta name="csrf-token" content="metaTok">'
        self.assertEqual(
            extract_csrf(html, cookie_header="XSRF-TOKEN=cookieTok; sid=1"),
            "cookieTok",
        )

    def test_none_found(self):
        self.assertIsNone(extract_csrf("<html><body>hello</body></html>"))


if __name__ == "__main__":
    unittest.main()
