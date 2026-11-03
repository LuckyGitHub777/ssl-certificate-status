"""Deterministic, offline checks for TLS certificate inspection and reporting."""

import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ssl_cert_status as tool


class ParseHostPortTests(unittest.TestCase):
    def test_default_port(self):
        self.assertEqual(tool.parse_host_port("example.invalid"), ("example.invalid", 443))

    def test_custom_port_and_whitespace(self):
        self.assertEqual(tool.parse_host_port(" example.invalid : 8443 "), ("example.invalid", 8443))

    def test_invalid_port_falls_back_to_default(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(tool.parse_host_port("example.invalid:not-a-port"), ("example.invalid", 443))
        self.assertIn("Invalid port", output.getvalue())


class InspectionBoundaryTests(unittest.TestCase):
    def test_mocked_certificate_is_reported_without_claiming_trust(self):
        certificate = MagicMock()
        certificate.get_notBefore.return_value = b"20300101000000Z"
        certificate.get_notAfter.return_value = b"20310101000000Z"
        certificate.get_subject.return_value = SimpleNamespace(CN="example.invalid")
        certificate.get_issuer.return_value = SimpleNamespace(CN="Example Synthetic CA")
        connection = MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b"synthetic-der-data"
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=context) as make_context,
            patch.object(tool.socket, "create_connection", return_value=connection) as connect,
            patch.object(tool.crypto, "load_certificate", return_value=certificate),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            tool.check_ssl_cert("example.invalid", 443)
        rendered = output.getvalue()
        self.assertIn("TLS Trust:      NOT VERIFIED", rendered)
        self.assertIn("example.invalid", rendered)
        self.assertIn("Example Synthetic CA", rendered)
        self.assertIn("2030", rendered)
        make_context.assert_called_once_with()
        connect.assert_called_once_with(("example.invalid", 443), timeout=10)

    def test_connection_error_is_reported_safely(self):
        with (
            patch.object(tool.ssl, "_create_unverified_context"),
            patch.object(tool.socket, "create_connection", side_effect=OSError("synthetic offline failure")),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            tool.check_ssl_cert("example.invalid")
        self.assertIn("Error connecting or retrieving certificate", output.getvalue())

    def test_missing_peer_certificate_is_not_reported_as_valid(self):
        connection = MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = None
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=context),
            patch.object(tool.socket, "create_connection", return_value=connection),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            tool.check_ssl_cert("example.invalid")
        self.assertIn("No certificate received", output.getvalue())
        self.assertNotIn("Valid Until", output.getvalue())


if __name__ == "__main__":
    unittest.main()
