"""IMEI validation and response classification tests (synthetic payloads only)."""
from __future__ import annotations

import unittest

from ..models import Decision, ErrorCode, RawResponse
from ..parser import (
    classify_response,
    classify_transport_error,
    clean_imei,
    extract_confirmation_url,
    extract_request_id,
    luhn_check,
    validate_imei,
)
from .support import FakeTransport, make_client, make_imei

from ..models import TransportError


def resp(status: int = 200, body: str = "", headers=None, set_cookies=None) -> RawResponse:
    return RawResponse(
        status=status,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        body=body,
        url="https://portal.test/x",
        elapsed_ms=1,
        set_cookies=set_cookies or [],
    )


class TestImeiValidation(unittest.TestCase):
    def test_valid_luhn_imei(self):
        imei = make_imei()
        ok, reason = validate_imei(imei)
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")
        self.assertTrue(luhn_check(imei))

    def test_cleaning_strips_separators(self):
        imei = make_imei()
        spaced = " ".join(imei[i:i + 2] for i in range(0, 15, 2))
        self.assertEqual(clean_imei(spaced), imei)
        ok, _ = validate_imei(spaced)
        self.assertTrue(ok)

    def test_wrong_length_fails(self):
        ok, reason = validate_imei("1234")
        self.assertFalse(ok)
        self.assertIn("15 digits", reason)

    def test_non_digit_fails(self):
        ok, reason = validate_imei("35A234567890123")
        self.assertFalse(ok)

    def test_empty_fails(self):
        ok, reason = validate_imei("   ")
        self.assertFalse(ok)
        self.assertIn("no IMEI", reason)

    def test_luhn_mismatch_is_soft_warning(self):
        imei = make_imei()
        # Flip the check digit -> still 15 digits, wrong checksum.
        bad = imei[:-1] + str((int(imei[-1]) + 1) % 10)
        self.assertFalse(luhn_check(bad))
        ok, reason = validate_imei(bad)
        self.assertTrue(ok)
        self.assertIn("Luhn", reason)


class TestExtraction(unittest.TestCase):
    def test_request_id(self):
        text = "Thank you. Your request number is NUL611583202886."
        self.assertEqual(extract_request_id(text), "NUL611583202886")

    def test_request_id_lowercase_normalized(self):
        self.assertEqual(extract_request_id("see nul1234567"), "NUL1234567")

    def test_no_request_id(self):
        self.assertIsNone(extract_request_id("nothing here"))

    def test_confirmation_url(self):
        text = ('Please confirm: https://www.att.com/deviceunlock/confirm?token=abc123 '
                "by tomorrow.")
        self.assertIn("confirm?token=abc123", extract_confirmation_url(text))

    def test_no_confirmation_url(self):
        self.assertIsNone(extract_confirmation_url("no links"))


class TestClassifyHttpLevels(unittest.TestCase):
    def test_5xx_is_temporary(self):
        c = classify_response(resp(503, "service unavailable"))
        self.assertEqual(c.decision, Decision.TEMPORARY_ERROR)
        self.assertEqual(c.confidence, "high")

    def test_429_is_temporary(self):
        c = classify_response(resp(429, ""))
        self.assertEqual(c.decision, Decision.TEMPORARY_ERROR)

    def test_challenge_page(self):
        c = classify_response(resp(403, "We detected unusual traffic. Please verify you are human."))
        self.assertEqual(c.decision, Decision.TEMPORARY_ERROR)
        self.assertIn("challenge_page", c.matched)

    def test_html_on_4xx(self):
        c = classify_response(resp(404, "<html><body>not found</body></html>"))
        self.assertEqual(c.decision, Decision.TEMPORARY_ERROR)
        self.assertIn("html_on_error", c.matched)

    def test_html_instead_of_json(self):
        c = classify_response(resp(200, "<!doctype html><html><div id='app'></div></html>"))
        self.assertEqual(c.decision, Decision.TEMPORARY_ERROR)
        self.assertIn("html_not_json", c.matched)

    def test_empty_body(self):
        c = classify_response(resp(200, ""))
        self.assertEqual(c.decision, Decision.TEMPORARY_ERROR)
        self.assertIn("empty_body", c.matched)

    def test_transport_timeout(self):
        c = classify_transport_error(TransportError("timed out", ErrorCode.TIMEOUT))
        self.assertEqual(c.decision, Decision.TEMPORARY_ERROR)
        self.assertIn("timeout", c.matched)


class TestClassifyDecisions(unittest.TestCase):
    """Each of the seven normalized decisions, from synthetic portal payloads."""

    def test_approved_explicit_field(self):
        c = classify_response(resp(200, '{"status": "approved", "message": "Your request has been approved"}'))
        self.assertEqual(c.decision, Decision.APPROVED)
        self.assertEqual(c.confidence, "high")

    def test_nested_envelope(self):
        c = classify_response(resp(200, '{"data": {"status": "rejected", "reason": "denied by policy"}}'))
        self.assertEqual(c.decision, Decision.REJECTED)
        self.assertEqual(c.confidence, "high")

    def test_pending_wording_beats_approved_wording(self):
        c = classify_response(resp(200, '{"message": "Your request is pending approval"}'))
        self.assertEqual(c.decision, Decision.PENDING)

    def test_pending_with_request_number(self):
        c = classify_response(
            resp(200, '{"message": "submitted and is being processed. Number NUL611583202886"}')
        )
        self.assertEqual(c.decision, Decision.PENDING)
        self.assertEqual(c.request_id, "NUL611583202886")

    def test_rejected_text(self):
        c = classify_response(resp(200, '{"message": "Your unlock request was rejected"}'))
        self.assertEqual(c.decision, Decision.REJECTED)

    def test_eligibility_failure_text(self):
        c = classify_response(
            resp(200, '{"message": "Your device does not meet the eligibility requirements"}')
        )
        self.assertEqual(c.decision, Decision.ELIGIBILITY_FAILED)

    def test_invalid_imei_text(self):
        c = classify_response(resp(200, '{"message": "Invalid IMEI number provided"}'))
        self.assertEqual(c.decision, Decision.INVALID_IMEI)

    def test_manual_review_text(self):
        c = classify_response(
            resp(200, '{"message": "Email confirmation is required. Select the link in the email within 24 hours."}')
        )
        self.assertEqual(c.decision, Decision.MANUAL_REVIEW)

    def test_under_review_field(self):
        c = classify_response(resp(200, '{"status": "under_review"}'))
        self.assertEqual(c.decision, Decision.MANUAL_REVIEW)

    def test_ineligible_field(self):
        c = classify_response(resp(200, '{"status": "not eligible"}'))
        self.assertEqual(c.decision, Decision.ELIGIBILITY_FAILED)

    def test_unknown_text_defaults_to_pending_low_confidence(self):
        c = classify_response(resp(200, '{"message": "we received your submission"}'))
        self.assertEqual(c.decision, Decision.PENDING)
        self.assertEqual(c.confidence, "low")
        self.assertIn("default_pending", c.matched)

    def test_list_payload_strings(self):
        c = classify_response(resp(200, '["request rejected"]'))
        self.assertEqual(c.decision, Decision.REJECTED)


class TestClassifyIntegrationWithClient(unittest.TestCase):
    def test_500_through_client_get(self):
        client, transport, _ = make_client()
        transport.queue(500, "boom")
        r = client.get("https://portal.test/x")
        c = classify_response(r)
        self.assertEqual(c.decision, Decision.TEMPORARY_ERROR)

    def test_missing_queue_raises_transport_error(self):
        client, transport, _ = make_client()
        with self.assertRaises(TransportError):
            client.get("https://portal.test/x", attempts=1)


if __name__ == "__main__":
    unittest.main()
