# SSL Certificate Status Checker

A lightweight Python 3 tool that checks the SSL/TLS certificate details of any hostname and port.  
It displays expiration dates, issuer details, and days remaining — useful for system admins, DevOps, or anyone who needs to monitor certificates.

---

## ✅ Features

- Retrieves SSL certificate for any domain and port (default: 443)
- Displays:
  - Common Name (Issued To)
  - Issuer CN
  - Validity period (Not Before / Not After)
  - Days remaining until expiration
- Accepts single host via CLI or prompts interactively
- Supports custom ports (e.g., `example.com:8443`)
- Gracefully handles invalid input, DNS errors, and interruptions
- Cross-platform compatible (Windows, macOS, Linux)

---

## 🚀 Usage

### Run with a domain (one-time check)

```bash
python ssl_cert_status.py example.com
```

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
  - Days Remaining: <calculated at runtime>
```

---

## TLS trust boundary

This tool inspects the certificate presented by a user-specified endpoint using an **unverified TLS connection**, allowing inspection even when a certificate is expired, self-signed, or otherwise untrusted. A displayed expiration date is **not** a certificate-trust, hostname-identity, revocation, or server-security verdict. Do not use the output alone to authenticate or approve a remote service.

---

## 📁 File

- `ssl_cert_status.py` — Main script

---

## ⚖️ License

This project is licensed under the [MIT License](LICENSE)
