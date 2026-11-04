"""Offline regression checks for trustworthy CLI inspection exit status."""

import contextlib
import io
import runpy
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ssl_cert_status as tool


class InspectionStatusTests(unittest.TestCase):
    def setUp(self):
        self.context = MagicMock()
        self.context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b"synthetic-der"
        self.cert = MagicMock()
        self.cert.get_notBefore.return_value = b"20300101000000Z"
        self.cert.get_notAfter.return_value = b"20310101000000Z"
        self.cert.get_subject.return_value = SimpleNamespace(CN="example.invalid")
        self.cert.get_issuer.return_value = SimpleNamespace(CN="Synthetic CA")

    def test_success_returns_true_but_never_asserts_trust(self):
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=self.context),
            patch.object(tool.socket, "create_connection", return_value=MagicMock()),
            patch.object(tool.crypto, "load_certificate", return_value=self.cert),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            result = tool.check_ssl_cert("example.invalid")
        self.assertIs(result, True)
        self.assertIn("TLS Trust:      NOT VERIFIED", out.getvalue())

    def test_connection_failure_returns_false(self):
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=self.context),
            patch.object(tool.socket, "create_connection", side_effect=OSError("offline test")),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            result = tool.check_ssl_cert("example.invalid")
        self.assertIs(result, False)
        self.assertIn("Error connecting or retrieving certificate", out.getvalue())

    def test_missing_peer_certificate_returns_false(self):
        self.context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = None
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=self.context),
            patch.object(tool.socket, "create_connection", return_value=MagicMock()),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            result = tool.check_ssl_cert("example.invalid")
        self.assertIs(result, False)
        self.assertIn("No certificate received", out.getvalue())

    def test_unparseable_certificate_returns_false(self):
        self.cert.get_notAfter.return_value = b"not-a-x509-date"
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=self.context),
            patch.object(tool.socket, "create_connection", return_value=MagicMock()),
            patch.object(tool.crypto, "load_certificate", return_value=self.cert),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            result = tool.check_ssl_cert("example.invalid")
        self.assertIs(result, False)
        self.assertIn("Failed to parse certificate", out.getvalue())

    def test_direct_command_failure_exits_one_without_network(self):
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=self.context),
            patch.object(tool.socket, "create_connection", side_effect=OSError("offline test")),
            patch.object(sys, "argv", ["ssl_cert_status.py", "example.invalid"]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as exit_result:
                runpy.run_path(tool.__file__, run_name="__main__")
        self.assertEqual(exit_result.exception.code, 1)

    def test_direct_command_success_exits_zero_without_network(self):
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=self.context),
            patch.object(tool.socket, "create_connection", return_value=MagicMock()),
            patch.object(tool.crypto, "load_certificate", return_value=self.cert),
            patch.object(sys, "argv", ["ssl_cert_status.py", "example.invalid"]),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            with self.assertRaises(SystemExit) as exit_result:
                runpy.run_path(tool.__file__, run_name="__main__")
        self.assertEqual(exit_result.exception.code, 0)
        self.assertIn("TLS Trust:      NOT VERIFIED", out.getvalue())


if __name__ == "__main__":
    unittest.main()
