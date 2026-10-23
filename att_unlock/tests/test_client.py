"""HTTP client behavior: retries, throttling, local pace gate, redaction."""
from __future__ import annotations

import logging
import unittest

from ..client import HttpClient
from ..models import RateLimitedLocally, TransportError
from .support import FakeClock, FakeTransport, make_client, make_config


class TestGetRetries(unittest.TestCase):
    def test_success_first_try(self):
        client, transport, clock = make_client()
        transport.queue(200, "ok")
        r = client.get("https://portal.test/a")
        self.assertEqual(r.status, 200)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(clock.slept, [])

    def test_retries_transport_error_then_succeeds(self):
        client, transport, clock = make_client()
        # First attempt fails at the network level: simulate by queueing an
        # empty transport via a one-shot wrapper.
        inner = transport

        class Flaky:
            def __init__(self):
                self.first = True

            def request(self, *a, **kw):
                if self.first:
                    self.first = False
                    raise TransportError("connection reset")
                return inner.request(*a, **kw)

        client.transport = Flaky()
        transport.queue(200, "ok")
        r = client.get("https://portal.test/a")
        self.assertEqual(r.status, 200)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(len(clock.slept), 1)  # backoff before retry

    def test_gives_up_after_attempts(self):
        client, transport, clock = make_client()
        with self.assertRaises(TransportError):
            client.get("https://portal.test/a", attempts=3)
        self.assertEqual(clock.slept, [1.0, 2.0])  # 2^0, 2^1

    def test_honors_retry_after_on_429(self):
        client, transport, clock = make_client()
        transport.queue(429, "slow down", headers={"Retry-After": "30"})
        transport.queue(200, "ok")
        r = client.get("https://portal.test/a")
        self.assertEqual(r.status, 200)
        self.assertEqual(clock.slept, [30.0])
        self.assertEqual(len(transport.calls), 2)

    def test_retry_after_capped(self):
        client, transport, clock = make_client()
        transport.queue(429, "", headers={"Retry-After": "99999"})
        transport.queue(200, "ok")
        client.get("https://portal.test/a")
        self.assertEqual(clock.slept, [900.0])  # capped at MAX_RETRY_AFTER

    def test_503_without_retry_after_uses_default(self):
        client, transport, clock = make_client()
        transport.queue(503, "")
        transport.queue(200, "ok")
        client.get("https://portal.test/a")
        self.assertEqual(clock.slept, [15.0])

    def test_last_attempt_429_returns_response_not_retry(self):
        client, transport, clock = make_client()
        transport.queue(429, "still slow", headers={"Retry-After": "5"})
        r = client.get("https://portal.test/a", attempts=1)
        self.assertEqual(r.status, 429)
        self.assertEqual(clock.slept, [])
        self.assertEqual(len(transport.calls), 1)


class TestPostNeverRetried(unittest.TestCase):
    def test_post_raises_on_transport_error_single_attempt(self):
        client, transport, clock = make_client()
        with self.assertRaises(TransportError):
            client.post("https://portal.test/a", json_body={"x": 1})
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(clock.slept, [])

    def test_post_500_returned_not_retried(self):
        client, transport, clock = make_client()
        transport.queue(500, "nope")
        r = client.post("https://portal.test/a", json_body={"x": 1})
        self.assertEqual(r.status, 500)
        self.assertEqual(len(transport.calls), 1)

    def test_post_sends_json(self):
        client, transport, clock = make_client()
        transport.queue(200, "{}")
        client.post("https://portal.test/a", json_body={"imei": "123", "agree": True})
        call = transport.calls[0]
        self.assertEqual(call["headers"].get("Content-Type"), "application/json")
        import json

        self.assertEqual(json.loads(call["data"]), {"imei": "123", "agree": True})


class TestLocalPaceGate(unittest.TestCase):
    def test_first_submit_allowed(self):
        client, _, _ = make_client()
        client.guard_submit()  # no raise

    def test_second_submit_within_interval_blocked(self):
        client, transport, clock = make_client()
        transport.queue(200, "{}").queue(200, "{}")
        client.get("https://portal.test/x")
        client.mark_submit()
        with self.assertRaises(RateLimitedLocally):
            client.guard_submit()

    def test_submit_allowed_after_interval(self):
        client, transport, clock = make_client()
        client.mark_submit()
        clock.t += 301  # default interval is 300s
        client.guard_submit()  # no raise

    def test_zero_interval_disables_gate(self):
        client, _, clock = make_client(make_config(min_submit_interval=0))
        client.mark_submit()
        client.guard_submit()  # no raise


class TestRedaction(unittest.TestCase):
    def test_logs_never_contain_cookie_values(self):
        from ..config import redact_dict

        out = redact_dict(
            {"Cookie": "sid=SUPERSECRET123", "csrfToken": "abc", "X-CSRF-Token": "t",
             "Accept": "application/json"}
        )
        self.assertEqual(out["Cookie"], "<redacted>")
        self.assertEqual(out["csrfToken"], "<redacted>")
        self.assertEqual(out["Accept"], "application/json")

    def test_nested_redaction(self):
        from ..config import redact_dict

        out = redact_dict({"data": {"session": "s3cr3t", "status": "pending"}})
        self.assertEqual(out["data"]["session"], "<redacted>")
        self.assertEqual(out["data"]["status"], "pending")


if __name__ == "__main__":
    unittest.main()
