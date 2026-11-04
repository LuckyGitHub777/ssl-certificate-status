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

def parse_host_port(input_str, default_port=443):
    """Parse hostname[:port], bare IPv6, or [IPv6]:port.

    Invalid or out-of-range explicit ports retain the historical default-port
    fallback. This is only endpoint parsing, not certificate trust validation.
    """
    value = input_str.strip()
    host = value
    port_text = None

    if value.startswith('['):
        closing = value.find(']')
        if closing != -1:
            candidate = value[1:closing].strip()
            remainder = value[closing + 1:].strip()
            if not remainder:
                host = candidate
            elif remainder.startswith(':'):
                host = candidate
                port_text = remainder[1:]
            # An invalid bracket suffix remains an invalid hostname, rather
            # than silently interpreting it as a legitimate IPv6 endpoint.
    elif value.count(':') == 1:
        host, port_text = value.rsplit(':', 1)
    # Multiple colons without brackets indicate a bare IPv6 literal.
    # A custom port for IPv6 must use the unambiguous [IPv6]:port syntax.

    if port_text is not None:
        try:
            port = int(port_text.strip())
            if not 1 <= port <= 65535:
                raise ValueError("Port outside TCP range")
            return host.strip(), port
        except ValueError:
            print(f"Invalid port. Using default {default_port}.")
    return host.strip(), default_port

def check_ssl_cert(hostname, port=443):
    """Connects to the server and prints SSL certificate information."""
    context = ssl._create_unverified_context()

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    print("No certificate received.")
                    return
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
    except Exception as e:
        print(f"\nError connecting or retrieving certificate: {e}\n")
        return

    try:
        date_format = '%Y%m%d%H%M%SZ'
        not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), date_format).replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), date_format).replace(tzinfo=timezone.utc)
        issued_to = x509.get_subject().CN
        issuer = x509.get_issuer().CN
        days_left = (not_after - datetime.now(timezone.utc)).days

        print(f"\nSSL Certificate Information for {hostname}:{port}\n")
        print("  - TLS Trust:      NOT VERIFIED (chain, hostname, revocation)")
        print(f"  - Issued To:      {issued_to}")
        print(f"  - Issuer:         {issuer}")
        print(f"  - Valid From:     {not_before}")
        print(f"  - Valid Until:    {not_after}")
        print(f"  - Days Remaining: {days_left} days\n")

    except Exception as parse_err:
        print(f"Failed to parse certificate: {parse_err}")

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        host_input = sys.argv[1]
        host, port = parse_host_port(host_input)
        check_ssl_cert(host, port)
    else:
        while True:
            try:
                user_input = input("Enter server hostname or IP: ").strip()
                if user_input.lower() in ('q', 'quit', 'exit'):
                    print("Exiting.")
                    break
                if not user_input:
                    continue
                host, port = parse_host_port(user_input)
                check_ssl_cert(host, port)
            except KeyboardInterrupt:
                print("\nInterrupted. Exiting.")
                break
