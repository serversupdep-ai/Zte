"""CLI end-to-end tests against the fake transport (no network)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from ..auth import AuthManager
from ..cli import main
from ..session import SessionState
from ..status import StatusService
from ..unlock import UnlockService
from .support import FakeClock, FakeTransport, make_client, make_config, make_imei

IMEI = make_imei()


class Services:
    """Mimics cli._Services but backed by the fake transport."""

    def __init__(self, config=None):
        self.config = config or make_config(session_cookie="sid=test")
        self.transport = FakeTransport()
        self.clock = FakeClock()
        self.client = make_client(self.config, self.transport, self.clock)[0]
        self.session = SessionState(cookie_header=self.config.session_cookie or "")
        self.auth = AuthManager(self.config, self.client)
        self.unlock = UnlockService(self.config, self.client, self.session, self.auth)
        self.status = StatusService(self.config, self.client, self.session)

    def run(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(argv, services_factory=lambda a: self)
        return rc, buf.getvalue()


class TestSubmitCommand(unittest.TestCase):
    def test_confirmation_gate_blocks_by_default(self):
        s = Services()
        with mock.patch("builtins.input", side_effect=EOFError):
            rc, out = s.run(["submit", "--imei", IMEI])
        self.assertEqual(rc, 130)
        self.assertEqual(s.transport.calls, [])  # no network I/O

    def test_json_output_and_pending_exit_code(self):
        s = Services()
        s.transport.queue(200, "<html>portal</html>")
        s.transport.queue(200, {"status": "approved", "message": "eligible"})
        s.transport.queue(200, {"status": "pending", "message": "submitted",
                                "requestNumber": "NUL611583202886"})
        rc, out = s.run(["submit", "--imei", IMEI, "--yes", "--json"])
        self.assertEqual(rc, 4)  # pending
        data = json.loads(out)
        self.assertEqual(data["decision"], "pending")
        self.assertEqual(data["request_id"], "NUL611583202886")
        self.assertIn("diagnostics", data)
        self.assertNotIn("TopSecret", out)  # no secrets ever in output

    def test_rejected_exit_code(self):
        s = Services()
        s.transport.queue(200, "<html>portal</html>")
        s.transport.queue(200, {"status": "rejected", "message": "no"})
        rc, out = s.run(["submit", "--imei", IMEI, "--yes"])
        self.assertEqual(rc, 3)

    def test_ineligible_exit_code(self):
        s = Services()
        s.transport.queue(200, "<html>portal</html>")
        s.transport.queue(200, {"status": "ineligible",
                                "message": "device does not meet the eligibility requirements"})
        rc, out = s.run(["submit", "--imei", IMEI, "--yes"])
        self.assertEqual(rc, 3)
        self.assertIn("NOT submitted", out)

    def test_invalid_imei_exit_code_no_network(self):
        s = Services()
        rc, out = s.run(["submit", "--imei", "123", "--yes"])
        self.assertEqual(rc, 2)
        self.assertEqual(s.transport.calls, [])


class TestStatusCommand(unittest.TestCase):
    def test_approved_exit_zero(self):
        s = Services()
        s.transport.queue(200, {"status": "approved"})
        rc, out = s.run(["status", "--imei", IMEI, "--request-id", "NUL611583202886"])
        self.assertEqual(rc, 0)
        self.assertIn("approved", out)

    def test_pending_exit_code(self):
        s = Services()
        s.transport.queue(200, {"status": "pending"})
        rc, _ = s.run(["status", "--imei", IMEI, "--request-id", "NUL611583202886"])
        self.assertEqual(rc, 4)

    def test_rejected_exit_code(self):
        s = Services()
        s.transport.queue(200, {"status": "rejected"})
        rc, _ = s.run(["status", "--imei", IMEI, "--request-id", "NUL611583202886"])
        self.assertEqual(rc, 3)


class TestEligibilityCommand(unittest.TestCase):
    def test_invalid_imei(self):
        s = Services()
        rc, _ = s.run(["eligibility", "--imei", "123"])
        self.assertEqual(rc, 2)
        self.assertEqual(s.transport.calls, [])

    def test_eligible(self):
        s = Services()
        s.transport.queue(200, {"status": "approved", "message": "eligible"})
        rc, out = s.run(["eligibility", "--imei", IMEI])
        self.assertEqual(rc, 0)


class TestDiagnoseCommand(unittest.TestCase):
    def test_offline_json_file_no_network(self):
        s = Services()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"status": 200, "body": "Your unlock request was rejected"}, fh)
            path = fh.name
        try:
            rc, out = s.run(["diagnose", "--imei", IMEI,
                             "--request-id", "NUL123", "--json-file", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 3)
        self.assertEqual(s.transport.calls, [])  # fully offline
        self.assertIn("DX_REJECTED", out)

    def test_offline_approved_body(self):
        s = Services()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"status": 200, "body": "Your request has been approved"}, fh)
            path = fh.name
        try:
            rc, out = s.run(["diagnose", "--json-file", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        self.assertIn("DX_APPROVED", out)

    def test_online_diagnose(self):
        s = Services()
        s.transport.queue(200, {"status": "pending"})
        rc, out = s.run(["diagnose", "--imei", IMEI, "--request-id", "NUL123"])
        self.assertEqual(rc, 4)
        self.assertIn("DX_PENDING", out)


class TestCalibrateCommand(unittest.TestCase):
    def test_masks_all_sensitive_values(self):
        s = Services()
        page = ('<html><meta name="csrf-token" content="tokabc123">'
                '<script src="/main.js"></script></html>')
        for _ in range(3):
            s.transport.queue(200, page,
                              set_cookies=["att_sessionid=supersecret123; Path=/"])
        rc, out = s.run(["calibrate"])
        self.assertEqual(rc, 0)
        self.assertIn("att_sessionid=<redacted>", out)
        self.assertNotIn("supersecret123", out)
        self.assertNotIn("tokabc123", out)
        self.assertIn("script", out)


if __name__ == "__main__":
    unittest.main()
