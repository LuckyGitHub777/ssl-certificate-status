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

    def test_direct_invalid_explicit_ports_fail_closed_without_network(self):
        for endpoint in ("example.invalid:bad", "example.invalid:0",
                         "example.invalid:65536", "example.invalid:",
                         "[::1]:65536"):
            with (
                self.subTest(endpoint=endpoint),
                patch.object(tool.socket, "create_connection") as connect,
                patch.object(sys, "argv", ["ssl_cert_status.py", endpoint]),
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                with self.assertRaises(SystemExit) as result:
                    runpy.run_path(tool.__file__, run_name="__main__")
            self.assertEqual(result.exception.code, 2)
            connect.assert_not_called()
            self.assertIn("Invalid port. Inspection cancelled.", out.getvalue())

    def test_interactive_invalid_explicit_port_skips_network(self):
        with (
            patch("builtins.input", side_effect=["example.invalid:bad", "exit"]),
            patch.object(tool.socket, "create_connection") as connect,
            patch.object(sys, "argv", ["ssl_cert_status.py"]),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            runpy.run_path(tool.__file__, run_name="__main__")
        connect.assert_not_called()
        self.assertIn("Invalid port. Inspection cancelled.", out.getvalue())
        self.assertIn("Exiting.", out.getvalue())

    def test_empty_and_malformed_hosts_fail_closed_without_connecting(self):
        for endpoint in ("", "  ", ":443", " :8443 ", "[]:443",
                         "[::1", "[::1]not-a-port-suffix"):
            with (
                self.subTest(endpoint=endpoint),
                patch.object(tool.socket, "create_connection") as connect,
                patch.object(sys, "argv", ["ssl_cert_status.py", endpoint]),
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                with self.assertRaises(SystemExit) as result:
                    runpy.run_path(tool.__file__, run_name="__main__")
            self.assertEqual(result.exception.code, 2)
            connect.assert_not_called()
            self.assertIn("Invalid hostname. Inspection cancelled.", out.getvalue())

    def test_interactive_invalid_hostname_never_connects(self):
        with (
            patch("builtins.input", side_effect=[":443", "[]:443", "exit"]),
            patch.object(tool.socket, "create_connection") as connect,
            patch.object(sys, "argv", ["ssl_cert_status.py"]),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            runpy.run_path(tool.__file__, run_name="__main__")
        connect.assert_not_called()
        self.assertEqual(out.getvalue().count("Invalid hostname. Inspection cancelled."), 2)
        self.assertIn("Exiting.", out.getvalue())

    def test_direct_valid_custom_port_still_inspects_selected_endpoint(self):
        with (
            patch.object(tool.ssl, "_create_unverified_context", return_value=self.context),
            patch.object(tool.socket, "create_connection", return_value=MagicMock()) as connect,
            patch.object(tool.crypto, "load_certificate", return_value=self.cert),
            patch.object(sys, "argv", ["ssl_cert_status.py", "example.invalid:8443"]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(tool.__file__, run_name="__main__")
        self.assertEqual(result.exception.code, 0)
        connect.assert_called_once_with(("example.invalid", 8443), timeout=10)

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
