"""Deterministic, offline checks for TLS certificate inspection and reporting."""

import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ssl_cert_status as tool


class ParseHostPortTests(unittest.TestCase):
    def test_empty_hostname_and_broken_brackets_are_invalid_even_with_fallback(self):
        for endpoint in ("", " ", ":443", "[]:443", "[::1", "[::1]junk"):
            with self.subTest(endpoint=endpoint):
                with self.assertRaisesRegex(ValueError, "Invalid hostname"):
                    tool.parse_host_port(endpoint)

    def test_default_port(self):
        self.assertEqual(tool.parse_host_port("example.invalid"), ("example.invalid", 443))

    def test_custom_port_and_whitespace(self):
        self.assertEqual(tool.parse_host_port(" example.invalid : 8443 "), ("example.invalid", 8443))

    def test_invalid_port_falls_back_to_default(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(tool.parse_host_port("example.invalid:not-a-port"), ("example.invalid", 443))
        self.assertIn("Invalid port", output.getvalue())


    def test_bare_ipv6_literal(self):
        self.assertEqual(tool.parse_host_port("2001:db8::1"), ("2001:db8::1", 443))
        self.assertEqual(tool.parse_host_port("::1"), ("::1", 443))

    def test_bracketed_ipv6_with_and_without_port(self):
        self.assertEqual(tool.parse_host_port("[::1]:8443"), ("::1", 8443))
        self.assertEqual(tool.parse_host_port("[2001:db8::1]"), ("2001:db8::1", 443))

    def test_out_of_range_and_missing_ports_keep_default(self):
        for port in ("0", "-1", "65536", ""):
            with self.subTest(port=port), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(tool.parse_host_port("example.invalid:" + port),
                                 ("example.invalid", 443))
            self.assertIn("Invalid port", output.getvalue())

    def test_bracketed_ipv6_invalid_port_keeps_default(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(tool.parse_host_port("[::1]:65536"), ("::1", 443))
        self.assertIn("Invalid port", output.getvalue())

    def test_custom_default_port_is_reported(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(tool.parse_host_port("example.invalid:bad", default_port=9443),
                             ("example.invalid", 9443))
        self.assertIn("9443", output.getvalue())


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

    def test_success_header_escapes_user_supplied_terminal_controls(self):
        # The caller-selected hostname is not a trusted certificate field.
        # Synthetic controls must never alter terminal output after inspection.
        hostname = "demo\x1b[31m.example.invalid"
        certificate = MagicMock()
        certificate.get_notBefore.return_value = b"20300101000000Z"
        certificate.get_notAfter.return_value = b"20310101000000Z"
        certificate.get_subject.return_value = SimpleNamespace(CN="example.invalid")
        certificate.get_issuer.return_value = SimpleNamespace(CN="Synthetic CA")
        connection = MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b"synthetic-der"
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=context),
            patch.object(tool.socket, "create_connection", return_value=connection) as connect,
            patch.object(tool.crypto, "load_certificate", return_value=certificate),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertTrue(tool.check_ssl_cert(hostname, 443))
        rendered = output.getvalue()
        self.assertIn("SSL Certificate Information for demo\\u001b[31m.example.invalid:443", rendered)
        self.assertNotIn("\x1b", rendered)
        connect.assert_called_once_with((hostname, 443), timeout=10)


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
