"""Diagnostics engine tests: each decision maps to its expected findings."""
from __future__ import annotations

import unittest

from ..diagnostics import PUBLISHED_REQUIREMENTS, diagnose
from ..models import Decision, EligibilityResult, StatusResult, SubmitResult
from .support import make_imei

IMEI = make_imei()


def codes(result):
    return {f.code for f in diagnose(result)}


class TestDecisionFindings(unittest.TestCase):
    def test_approved(self):
        r = StatusResult(decision=Decision.APPROVED, imei=IMEI, request_id="NUL1")
        self.assertIn("DX_APPROVED", codes(r))

    def test_pending(self):
        r = StatusResult(decision=Decision.PENDING, imei=IMEI, request_id="NUL1")
        self.assertIn("DX_PENDING", codes(r))

    def test_rejected_includes_published_requirements(self):
        r = StatusResult(decision=Decision.REJECTED, imei=IMEI, request_id="NUL1")
        found = diagnose(r)
        codes_ = {f.code for f in found}
        self.assertIn("DX_REJECTED", codes_)
        self.assertIn("DX_REJECTED_REQUIREMENTS", codes_)
        reqs = next(f for f in found if f.code == "DX_REJECTED_REQUIREMENTS")
        self.assertEqual(len(reqs.actions), len(PUBLISHED_REQUIREMENTS))
        self.assertTrue(any("60+ days" in a for a in reqs.actions))

    def test_eligibility_failed(self):
        r = StatusResult(decision=Decision.ELIGIBILITY_FAILED, imei=IMEI)
        self.assertIn("DX_ELIGIBILITY", codes(r))

    def test_invalid_imei(self):
        r = StatusResult(decision=Decision.INVALID_IMEI, imei=IMEI)
        self.assertIn("DX_INVALID_IMEI", codes(r))

    def test_manual_review(self):
        r = StatusResult(decision=Decision.MANUAL_REVIEW, imei=IMEI, request_id="NUL1")
        found = diagnose(r)
        self.assertIn("DX_MANUAL_REVIEW", {f.code for f in found})
        review = next(f for f in found if f.code == "DX_MANUAL_REVIEW")
        self.assertTrue(any("24 hours" in a for a in review.actions))

    def test_temporary_error(self):
        r = StatusResult(decision=Decision.TEMPORARY_ERROR, imei=IMEI)
        self.assertIn("DX_TEMPORARY", codes(r))


class TestStructuralFindings(unittest.TestCase):
    def test_waf_challenge(self):
        r = SubmitResult(decision=Decision.TEMPORARY_ERROR, imei=IMEI,
                         matched=["challenge_page"])
        self.assertIn("DX_WAF_CHALLENGE", codes(r))

    def test_endpoint_drift(self):
        r = StatusResult(decision=Decision.TEMPORARY_ERROR, imei=IMEI,
                         matched=["html_not_json"])
        self.assertIn("DX_ENDPOINT_DRIFT", codes(r))

    def test_missing_request_id_after_accept(self):
        r = SubmitResult(decision=Decision.PENDING, imei=IMEI, request_id=None)
        self.assertIn("DX_NO_REQUEST_ID", codes(r))

    def test_request_id_present_no_warning(self):
        r = SubmitResult(decision=Decision.PENDING, imei=IMEI, request_id="NUL1")
        self.assertNotIn("DX_NO_REQUEST_ID", codes(r))

    def test_low_confidence_note(self):
        r = StatusResult(decision=Decision.PENDING, imei=IMEI,
                         request_id="NUL1", confidence="low")
        self.assertIn("DX_LOW_CONFIDENCE", codes(r))

    def test_high_confidence_no_note(self):
        r = StatusResult(decision=Decision.APPROVED, imei=IMEI,
                         request_id="NUL1", confidence="high")
        self.assertNotIn("DX_LOW_CONFIDENCE", codes(r))

    def test_eligibility_result_also_diagnosable(self):
        r = EligibilityResult(decision=Decision.ELIGIBILITY_FAILED, eligible=False,
                              imei=IMEI, message="not eligible")
        self.assertIn("DX_ELIGIBILITY", codes(r))

    def test_diagnostics_serialize(self):
        r = StatusResult(decision=Decision.REJECTED, imei=IMEI, request_id="NUL1")
        for f in diagnose(r):
            d = f.to_dict()
            self.assertEqual(set(d), {"code", "severity", "title", "detail",
                                      "actions", "references"})


if __name__ == "__main__":
    unittest.main()
