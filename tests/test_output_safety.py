"""Offline tests for privacy-safe certificate-inspector console output."""

import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ssl_cert_status as tool


class OutputSafetyTests(unittest.TestCase):
    def test_text_field_escapes_control_and_direction_formatters(self):
        original = "Synthetic" + chr(10) + chr(27) + "[31m" + chr(0x202E)
        display = tool._safe_field(original)
        for forbidden in (chr(10), chr(27), chr(0x202E)):
            self.assertNotIn(forbidden, display)
        for escaped in ("u000a", "u001b", "u202e"):
            self.assertIn(chr(92) + escaped, display)
        self.assertLessEqual(len(tool._safe_field("x" * 1000)), 256)

    def test_connection_exception_does_not_echo_sensitive_input(self):
        marker = "synthetic-private-value"
        with (
            patch.object(tool.ssl, "_create_unverified_context"),
            patch.object(tool.socket, "create_connection",
                         side_effect=OSError(marker + chr(10) + chr(27) + "[2J")),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            result = tool.check_ssl_cert("example.invalid")
        self.assertIs(result, False)
        self.assertIn("Error connecting or retrieving certificate", out.getvalue())
        self.assertNotIn(marker, out.getvalue())
        self.assertNotIn(chr(27), out.getvalue())

    def test_untrusted_certificate_labels_are_terminal_safe(self):
        cert = MagicMock()
        cert.get_notBefore.return_value = b"20300101000000Z"
        cert.get_notAfter.return_value = b"20310101000000Z"
        cert.get_subject.return_value = SimpleNamespace(CN="Synthetic" + chr(10) + "subject")
        cert.get_issuer.return_value = SimpleNamespace(CN="Issuer" + chr(27) + "[2J" + chr(0x202E))
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b"synthetic-der"
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=context),
            patch.object(tool.socket, "create_connection", return_value=MagicMock()),
            patch.object(tool.crypto, "load_certificate", return_value=cert),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            result = tool.check_ssl_cert("example.invalid")
        rendered = out.getvalue()
        self.assertIs(result, True)
        self.assertIn("TLS Trust:      NOT VERIFIED", rendered)
        self.assertIn("Synthetic" + chr(92) + "u000asubject", rendered)
        self.assertIn("Issuer" + chr(92) + "u001b[2J" + chr(92) + "u202e", rendered)
        self.assertNotIn(chr(27), rendered)
        self.assertNotIn(chr(0x202E), rendered)

    def test_parse_exception_not_echoed(self):
        cert = MagicMock()
        cert.get_notBefore.return_value = b"synthetic-private-value"
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b"synthetic-der"
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=context),
            patch.object(tool.socket, "create_connection", return_value=MagicMock()),
            patch.object(tool.crypto, "load_certificate", return_value=cert),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            result = tool.check_ssl_cert("example.invalid")
        self.assertIs(result, False)
        self.assertIn("Failed to parse certificate.", out.getvalue())
        self.assertNotIn("synthetic-private-value", out.getvalue())


if __name__ == "__main__":
    unittest.main()
