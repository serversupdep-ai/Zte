"""Status lookup and opt-in polling tests."""
from __future__ import annotations

import unittest

from ..models import Decision
from ..session import SessionState
from ..status import StatusService, normalize_request_id
from .support import FakeClock, FakeTransport, make_client, make_config, make_imei

IMEI = make_imei()


def build():
    config = make_config(session_cookie="sid=test")
    transport = FakeTransport()
    clock = FakeClock()
    client = make_client(config, transport, clock)[0]
    svc = StatusService(config, client, SessionState(cookie_header="sid=test"))
    return svc, transport, clock


class TestStatusLookup(unittest.TestCase):
    def test_approved(self):
        svc, transport, clock = build()
        transport.queue(
            200,
            {"status": "approved", "message": "approved",
             "updatedAt": "2026-09-09T10:00:00Z"},
        )
        result = svc.get_status(IMEI, "NUL611583202886")
        self.assertEqual(result.decision, Decision.APPROVED)
        self.assertEqual(result.request_id, "NUL611583202886")
        self.assertEqual(result.updated_at, "2026-09-09T10:00:00Z")

    def test_pending(self):
        svc, transport, clock = build()
        transport.queue(200, {"status": "pending", "message": "in process"})
        result = svc.get_status(IMEI, "NUL611583202886")
        self.assertEqual(result.decision, Decision.PENDING)

    def test_invalid_imei_local(self):
        svc, transport, clock = build()
        result = svc.get_status("123", "NUL611583202886")
        self.assertEqual(result.decision, Decision.INVALID_IMEI)
        self.assertEqual(transport.calls, [])

    def test_request_id_normalized_in_url(self):
        svc, transport, clock = build()
        transport.queue(200, {"status": "pending"})
        svc.get_status(IMEI, "nul 611583202886")
        url = transport.last_url()
        self.assertIn(f"imei={IMEI}", url)
        self.assertIn("requestNumber=NUL611583202886", url)

    def test_non_standard_request_id_still_queries(self):
        svc, transport, clock = build()
        transport.queue(200, {"status": "pending"})
        result = svc.get_status(IMEI, "ABC123")
        self.assertEqual(result.decision, Decision.PENDING)
        self.assertIn("requestNumber=ABC123", transport.last_url())


class TestWaitForDecision(unittest.TestCase):
    def test_polls_until_approved(self):
        svc, transport, clock = build()
        transport.queue(200, {"status": "pending"})
        transport.queue(200, {"status": "pending"})
        transport.queue(200, {"status": "approved"})
        results = svc.wait_for_decision(IMEI, "NUL611583202886",
                                        max_checks=5, interval=600)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[-1].decision, Decision.APPROVED)
        self.assertEqual(clock.slept, [600, 600])
        self.assertEqual(len(transport.calls), 3)

    def test_stops_on_rejection(self):
        svc, transport, clock = build()
        transport.queue(200, {"status": "rejected"})
        results = svc.wait_for_decision(IMEI, "NUL611583202886",
                                        max_checks=5, interval=600)
        self.assertEqual(len(results), 1)
        self.assertEqual(clock.slept, [])

    def test_respects_max_checks(self):
        svc, transport, clock = build()
        for _ in range(4):
            transport.queue(200, {"status": "pending"})
        results = svc.wait_for_decision(IMEI, "NUL611583202886",
                                        max_checks=4, interval=600)
        self.assertEqual(len(results), 4)
        self.assertEqual(clock.slept, [600, 600, 600])


class TestNormalizeRequest_id(unittest.TestCase):
    def test_trims_and_uppercases(self):
        self.assertEqual(normalize_request_id(" nul 123456 "), "NUL123456")
        self.assertEqual(normalize_request_id("NUL-123456"), "NUL123456")


if __name__ == "__main__":
    unittest.main()
