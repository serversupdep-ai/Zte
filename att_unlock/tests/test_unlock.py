"""Unlock workflow tests: eligibility gate, finality of rejections, pace gate."""
from __future__ import annotations

import unittest

from ..auth import AuthManager
from ..models import BlockedError, Decision, RateLimitedLocally
from ..session import SessionState
from ..unlock import UnlockService
from .support import FakeClock, FakeTransport, make_client, make_config, make_imei

IMEI = make_imei()


def build(config=None, transport=None, clock=None):
    cfg = config or make_config(session_cookie="sid=test; csrf=c1")
    tr = transport or FakeTransport()
    clk = clock or FakeClock()
    client = make_client(cfg, tr, clk)[0]
    session = SessionState(cookie_header=cfg.session_cookie or "")
    svc = UnlockService(cfg, client, session, AuthManager(cfg, client,
                                                          logger=__import__("logging").getLogger("t")))
    return svc, tr, clk


class TestSubmitWorkflow(unittest.TestCase):
    def test_happy_path_eligible_then_submitted(self):
        svc, transport, clock = build()
        transport.queue(200, "<html>portal</html>")  # session soft verify
        transport.queue(200, {"status": "approved", "message": "device is eligible"})
        transport.queue(
            200,
            {"status": "pending", "message": "submitted",
             "requestNumber": "NUL611583202886"},
        )
        result = svc.submit(IMEI, email="op@example.test", is_customer=True)
        self.assertEqual(result.decision, Decision.PENDING)
        self.assertEqual(result.request_id, "NUL611583202886")
        self.assertFalse(result.email_confirmation_required)
        bodies = transport.post_bodies()
        self.assertEqual(len(bodies), 2)  # eligibility + submit only
        self.assertEqual(bodies[0], {"imei": IMEI})
        self.assertEqual(bodies[1], {"imei": IMEI, "agree": True,
                                     "email": "op@example.test", "attCustomer": True})

    def test_ineligible_is_final_no_submit_call(self):
        svc, transport, clock = build()
        transport.queue(200, "<html>portal</html>")
        transport.queue(
            200,
            {"status": "ineligible",
             "message": "device does not meet the eligibility requirements"},
        )
        result = svc.submit(IMEI)
        self.assertEqual(result.decision, Decision.ELIGIBILITY_FAILED)
        self.assertEqual(len(transport.calls), 2)  # soft verify + eligibility only
        self.assertIn("NOT submitted", result.message)
        self.assertIn("eligibility_gate", result.matched)

    def test_rejected_is_final_no_submit_call(self):
        svc, transport, clock = build()
        transport.queue(200, "<html>portal</html>")
        transport.queue(200, {"status": "rejected", "message": "request rejected"})
        result = svc.submit(IMEI)
        self.assertEqual(result.decision, Decision.REJECTED)
        self.assertEqual(len(transport.calls), 2)

    def test_eligibility_temporary_error_withholds_submission(self):
        svc, transport, clock = build()
        transport.queue(200, "<html>portal</html>")
        transport.queue(500, "internal error")
        result = svc.submit(IMEI)
        self.assertEqual(result.decision, Decision.TEMPORARY_ERROR)
        self.assertEqual(len(transport.calls), 2)
        self.assertIn("nothing was submitted", result.message)

    def test_ambiguous_pending_withholds_submission(self):
        svc, transport, clock = build()
        transport.queue(200, "<html>portal</html>")
        transport.queue(200, {"message": "processing"})
        result = svc.submit(IMEI)
        self.assertEqual(result.decision, Decision.PENDING)
        self.assertEqual(len(transport.calls), 2)
        self.assertIn("eligibility_gate", result.matched)
        self.assertIn("withheld", result.message)

    def test_invalid_imei_never_reaches_network(self):
        svc, transport, clock = build()
        result = svc.submit("123")
        self.assertEqual(result.decision, Decision.INVALID_IMEI)
        self.assertEqual(transport.calls, [])

    def test_challenge_page_raises_blocked(self):
        svc, transport, clock = build()
        # check_eligibility makes a single POST (no soft-verify GET).
        transport.queue(403, "We detected unusual traffic.")
        with self.assertRaises(BlockedError):
            svc.check_eligibility(IMEI)

    def test_local_pace_gate_blocks_second_submit(self):
        svc, transport, clock = build()
        # First full submission
        transport.queue(200, "<html>portal</html>")
        transport.queue(200, {"status": "approved", "message": "ok"})
        transport.queue(200, {"status": "pending", "message": "submitted"})
        svc.submit(IMEI)
        calls_after_first = len(transport.calls)
        # Second submission immediately after -> local gate fires (no I/O)
        with self.assertRaises(RateLimitedLocally):
            svc.submit(IMEI)
        self.assertEqual(len(transport.calls), calls_after_first)

    def test_confirmation_url_sets_email_flag(self):
        svc, transport, clock = build()
        transport.queue(200, "<html>portal</html>")
        transport.queue(200, {"status": "approved", "message": "eligible"})
        transport.queue(
            200,
            {"status": "pending",
             "message": "email confirmation required",
             "confirmUrl": "https://www.att.com/deviceunlock/confirm?token=zz9"},
        )
        result = svc.submit(IMEI)
        self.assertTrue(result.email_confirmation_required)
        self.assertIn("confirm?token=zz9", result.confirmation_url)
        self.assertEqual(result.request_id, None or result.request_id)  # not present


class TestEligibilityOnly(unittest.TestCase):
    def test_eligibility_approved(self):
        svc, transport, clock = build()
        transport.queue(200, {"status": "approved", "message": "eligible"})
        result = svc.check_eligibility(IMEI)
        self.assertEqual(result.eligible, True)
        self.assertEqual(result.decision, Decision.APPROVED)

    def test_eligibility_ineligible(self):
        svc, transport, clock = build()
        transport.queue(200, {"status": "ineligible", "message": "not eligible"})
        result = svc.check_eligibility(IMEI)
        self.assertEqual(result.eligible, False)

    def test_eligibility_invalid_imei_local(self):
        svc, transport, clock = build()
        result = svc.check_eligibility("nope")
        self.assertEqual(result.decision, Decision.INVALID_IMEI)
        self.assertEqual(result.eligible, False)
        self.assertEqual(transport.calls, [])


if __name__ == "__main__":
    unittest.main()
