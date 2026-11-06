#!/usr/bin/env python3

import ssl
import socket
import sys
import os
from datetime import datetime, timezone

try:
    from OpenSSL import crypto
except ImportError:
    print("Missing dependency: pyOpenSSL. Install with: pip install pyOpenSSL")
    sys.exit(1)

# Ensure UTF-8 output on Windows
if os.name == 'nt':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass  # Safe fallback for older Python versions

def parse_host_port(input_str, default_port=443, *, reject_invalid_port=False):
    """Parse hostname[:port], bare IPv6, or [IPv6]:port.

    The importable parser preserves default-port fallback unless explicitly
    asked to reject invalid ports. This is not TLS trust validation.
    """
    value = input_str.strip()
    if not value:
        raise ValueError("Invalid hostname")
    host = value
    port_text = None

    if value.startswith('['):
        closing = value.find(']')
        if closing == -1:
            raise ValueError("Invalid hostname")
        if closing != -1:
            candidate = value[1:closing].strip()
            remainder = value[closing + 1:].strip()
            if not remainder:
                host = candidate
            elif remainder.startswith(':'):
                host = candidate
                port_text = remainder[1:]
            else:
                raise ValueError("Invalid hostname")
            # Invalid bracket suffixes must not reach network resolution.
    elif value.count(':') == 1:
        host, port_text = value.rsplit(':', 1)
    # Multiple colons without brackets indicate a bare IPv6 literal.
    # A custom port for IPv6 must use the unambiguous [IPv6]:port syntax.

    if not host.strip():
        raise ValueError("Invalid hostname")

    if port_text is not None:
        try:
            port = int(port_text.strip())
            if not 1 <= port <= 65535:
                raise ValueError("Port outside TCP range")
            return host.strip(), port
        except ValueError:
            if reject_invalid_port:
                raise ValueError("Invalid port") from None
            print(f"Invalid port. Using default {default_port}.")
    return host.strip(), default_port

def _safe_field(value):
    """Render untrusted certificate text without terminal control characters."""
    return "".join(
        ch if ch.isprintable() else f"\\u{ord(ch):04x}"
        for ch in str(value)
    )[:256]


def check_ssl_cert(hostname, port=443):
    """Inspect a presented certificate; return True only after parsing it."""
    context = ssl._create_unverified_context()

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    print("No certificate received.")
                    return False
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
    except Exception:
        # Exceptions may include caller input, URLs or local machine details.
        print("\nError connecting or retrieving certificate.\n")
        return False

    try:
        date_format = '%Y%m%d%H%M%SZ'
        not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), date_format).replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), date_format).replace(tzinfo=timezone.utc)
        issued_to = x509.get_subject().CN
        issuer = x509.get_issuer().CN
        days_left = (not_after - datetime.now(timezone.utc)).days

        print(f"\nSSL Certificate Information for {_safe_field(hostname)}:{_safe_field(port)}\n")
        print("  - TLS Trust:      NOT VERIFIED (chain, hostname, revocation)")
        print(f"  - Issued To:      {_safe_field(issued_to)}")
        print(f"  - Issuer:         {_safe_field(issuer)}")
        print(f"  - Valid From:     {not_before}")
        print(f"  - Valid Until:    {not_after}")
        print(f"  - Days Remaining: {days_left} days\n")
        return True

    except Exception:
        print("Failed to parse certificate.")
        return False

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        host_input = sys.argv[1]
        try:
            host, port = parse_host_port(host_input, reject_invalid_port=True)
        except ValueError as error:
            print(f"{error}. Inspection cancelled.")
            sys.exit(2)
        sys.exit(0 if check_ssl_cert(host, port) else 1)
    else:
        while True:
            try:
                user_input = input("Enter server hostname or IP: ").strip()
                if user_input.lower() in ('q', 'quit', 'exit'):
                    print("Exiting.")
                    break
                if not user_input:
                    continue
                try:
                    host, port = parse_host_port(user_input, reject_invalid_port=True)
                except ValueError as error:
                    print(f"{error}. Inspection cancelled.")
                    continue
                check_ssl_cert(host, port)
            except KeyboardInterrupt:
                print("\nInterrupted. Exiting.")
                break
