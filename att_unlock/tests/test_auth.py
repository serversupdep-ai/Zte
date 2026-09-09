"""Authentication tests: cookie mode, login mode with human MFA, no secret leaks."""
from __future__ import annotations

import logging
import unittest

from ..auth import AuthManager
from ..models import AuthError
from ..session import SessionState
from .support import FakeTransport, make_client, make_config


class _LogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())

    @property
    def text(self):
        return "\n".join(self.records)


def _manager(config, transport, clock, mfa_prompt=None, logger=None):
    client = _make_client(config, transport, clock)
    log = logger or logging.getLogger("att_unlock.auth.test")
    log.setLevel(logging.DEBUG)
    return AuthManager(config, client, mfa_prompt=mfa_prompt or (lambda q: ""), logger=log)


def _make_client(config, transport, clock):
    from ..client import HttpClient

    return HttpClient(config, transport=transport, sleep=clock.sleep, now=clock.now)


class TestCookieMode(unittest.TestCase):
    def test_cookie_session_used_without_login_calls(self):
        config = make_config(session_cookie="sid=abc123; csrf=c1")
        transport = FakeTransport()
        from .support import FakeClock

        clock = FakeClock()
        transport.queue(200, "<html>portal</html>")  # soft verify
        mgr = _manager(config, transport, clock)
        self.assertEqual(mgr.mode(), "cookie")
        session = mgr.ensure(SessionState())
        self.assertTrue(session.authenticated)
        self.assertEqual(session.cookies()["sid"], "abc123")
        methods = [c["method"] for c in transport.calls]
        self.assertEqual(methods, ["GET"])  # soft verify only; no login POST

    def test_soft_verify_challenge_warns_but_proceeds(self):
        config = make_config(session_cookie="sid=abc123")
        transport = FakeTransport()
        from .support import FakeClock

        clock = FakeClock()
        transport.queue(403, "We detected unusual traffic. Verify you are human.")
        mgr = _manager(config, transport, clock)
        session = mgr.ensure(SessionState())
        self.assertTrue(session.authenticated)  # continues; API call is the real test


class TestNoMaterial(unittest.TestCase):
    def test_raises_actionable_auth_error(self):
        config = make_config()
        transport = FakeTransport()
        from .support import FakeClock

        clock = FakeClock()
        mgr = _manager(config, transport, clock)
        self.assertEqual(mgr.mode(), "none")
        with self.assertRaises(AuthError) as ctx:
            mgr.ensure(SessionState())
        self.assertIn("ATT_UNLOCK_SESSION_COOKIE", str(ctx.exception))
        self.assertEqual(transport.calls, [])  # no network I/O attempted


class TestLoginMode(unittest.TestCase):
    def test_login_with_human_mfa(self):
        config = make_config(username="op@example.test", password="TopSecret99!")
        transport = FakeTransport()
        from .support import FakeClock

        clock = FakeClock()
        prompts = []
        transport.queue(
            200,
            '<html><meta name="csrf-token" content="tokLogin1"></html>',
            set_cookies=["jsessionid=J1; Path=/"],
        )
        transport.queue(200, "Please enter your one-time verification code.")
        transport.queue(200, '{"success": true}')
        mgr = _manager(
            config, transport, clock,
            mfa_prompt=lambda q: prompts.append(q) or "246810",
        )
        session = mgr.ensure(SessionState())
        self.assertEqual(session.cookies()["jsessionid"], "J1")
        self.assertEqual(session.csrf_token, "tokLogin1")
        self.assertEqual(len(prompts), 1)  # MFA asked of the human exactly once
        methods = [c["method"] for c in transport.calls]
        self.assertEqual(methods, ["GET", "POST", "POST"])
        # The MFA code was sent in the second POST body
        import json

        self.assertEqual(transport.post_bodies()[1]["code"], "246810")

    def test_password_never_logged(self):
        config = make_config(username="op@example.test", password="TopSecret99!")
        transport = FakeTransport()
        from .support import FakeClock

        clock = FakeClock()
        transport.queue(
            200, '<html><meta name="csrf-token" content="t"></html>',
            set_cookies=["jsessionid=J1; Path=/"],
        )
        transport.queue(200, "one-time code required")
        transport.queue(200, '{"success": true}')
        logger = logging.getLogger("att_unlock.auth.secrettest")
        capture = _LogCapture()
        logger.addHandler(capture)
        try:
            mgr = _manager(config, transport, clock,
                           mfa_prompt=lambda q: "000000", logger=logger)
            mgr.ensure(SessionState())
        finally:
            logger.removeHandler(capture)
        self.assertNotIn("TopSecret99!", capture.text)
        self.assertNotIn("000000", capture.text)

    def test_login_failure_raises(self):
        config = make_config(username="op@example.test", password="WrongPass1")
        transport = FakeTransport()
        from .support import FakeClock

        clock = FakeClock()
        transport.queue(200, "<html>login</html>", set_cookies=["jsessionid=J1; Path=/"])
        transport.queue(400, "invalid credentials")
        mgr = _manager(config, transport, clock)
        with self.assertRaises(AuthError):
            mgr.ensure(SessionState())

    def test_mfa_aborted_raises_auth_error(self):
        config = make_config(username="op@example.test", password="x")
        transport = FakeTransport()
        from .support import FakeClock

        clock = FakeClock()

        def abort(q):
            raise EOFError

        transport.queue(200, "<html>login</html>", set_cookies=["jsessionid=J1; Path=/"])
        transport.queue(401, "mfa required")
        mgr = _manager(config, transport, clock, mfa_prompt=abort)
        with self.assertRaises(AuthError) as ctx:
            mgr.ensure(SessionState())
        self.assertIn("cookie mode", str(ctx.exception))

    def test_login_page_challenge_blocks(self):
        config = make_config(username="op@example.test", password="x")
        transport = FakeTransport()
        from .support import FakeClock

        clock = FakeClock()
        transport.queue(403, "request blocked - verify you are human")
        mgr = _manager(config, transport, clock)
        with self.assertRaises(AuthError) as ctx:
            mgr.ensure(SessionState())
        self.assertIn("challenge", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
