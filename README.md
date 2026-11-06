# SSL Certificate Status Checker

**Inspect the certificate a website presents, including its issuer and expiration date.** A small Python CLI for IT operations, monitoring, and learning how TLS certificates are structured.

## Try it

```bash
python -m pip install -r requirements.txt
python ssl_cert_status.py example.com
```

Replace `example.com` with a hostname you are authorized to inspect. You will see the presented certificate's dates, issuer and days remaining. **Inspection does not verify certificate trust, hostname identity, or endpoint safety**—see [TLS trust boundary](#tls-trust-boundary).

---

## ✅ Features

- Retrieves SSL certificate for any domain and port (default: 443)
- Displays:
  - Common Name (Issued To)
  - Issuer CN
  - Validity period (Not Before / Not After)
  - Days remaining until expiration
  - Explicit date-window classification (not yet valid, expired, within dates, or invalid date range)
- Accepts single host via CLI or prompts interactively
- Supports custom ports (e.g., `example.com:8443`)
- Supports bare IPv6 addresses and bracketed IPv6 with custom ports (e.g., `[2001:db8::1]:8443`)
- The CLI rejects malformed or out-of-range explicit ports without connecting; one-shot commands return exit status 2. The importable parser retains its historical fallback by default.
- Empty hostnames and malformed bracket syntax are rejected before any network connection, including in interactive mode.
- Gracefully handles invalid input, DNS errors, and interruptions
- Cross-platform compatible (Windows, macOS, Linux)

---

## 🚀 Usage

### Run with a domain (one-time check)

```bash
python ssl_cert_status.py example.com
```

### Exit status for automated checks

When you provide a hostname as a command-line argument, the process exits with **0** after successfully retrieving and parsing a certificate, or **1** when inspection fails (connection error, missing peer certificate, or unparseable certificate). Malformed explicit TCP ports, empty hostnames, and malformed bracketed endpoints exit with **2** without opening a connection. In interactive mode, the invalid entry is skipped so the next prompt can continue. The interactive prompt remains available for multiple lookups. An internally inconsistent certificate validity range (not-after at or before not-before) is explicitly labeled **INVALID DATE RANGE** and also exits with status **1**; it must not be treated as a successful inspection. A successful inspection exit status is **not** evidence of certificate-chain trust, hostname validation, revocation status, or endpoint safety; see the TLS trust boundary below.

### Interactive mode (multiple lookups)

```bash
python ssl_cert_status.py
```

You’ll be prompted to enter hostnames (like `google.com` or `site.com:443`).  
To exit, type: `exit`, `quit`, or `q`.

---

## 📦 Requirements

- Python 3.11–3.13 (tested in GitHub Actions; other versions are not verified)
- [`pyOpenSSL`](https://pypi.org/project/pyOpenSSL/)

Install via pip:

```bash
pip install pyOpenSSL
```

---

## 🔎 Illustrative Output (fictional values)

The following is an example of the CLI format, **not a live certificate reading**. Real values and days remaining depend on the endpoint and the date of the check.

```text
Enter server hostname or IP: example.com

SSL Certificate Information for example.com:443

  - Issued To:      example.com
  - Issuer:         Example CA
  - Valid From:     2030-06-01 00:00:00+00:00
  - Valid Until:    2030-09-01 00:00:00+00:00
  - Date Window:    <classified at runtime; does not verify trust>
  - Days Remaining: <calculated at runtime>
```

---

## TLS trust boundary

This tool inspects the certificate presented by a user-specified endpoint using an **unverified TLS connection**, allowing inspection even when a certificate is expired, self-signed, or otherwise untrusted. The date-window label describes only the relationship between the certificate's stated validity dates and the current UTC time; **WITHIN DATES is not a trusted/secure verdict**. A displayed expiration date is **not** a certificate-trust, hostname-identity, revocation, or server-security verdict. Do not use the output alone to authenticate or approve a remote service.

---

## 📁 File

- `ssl_cert_status.py` — Main script

---

## ⚖️ License

This project is licensed under the [MIT License](LICENSE)
