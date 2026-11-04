# AUTH-002 — Incomplete or unsafe security scheme reference

Flags undefined security scheme names and HTTP Basic authentication paired
with an HTTP server URL. It inspects the contract and cannot verify deployment
configuration.

**Review:** define each referenced scheme and serve credentials only over
HTTPS.

**References:** OWASP API Security Top 10 API8:2023 Security Misconfiguration;
CWE-16 Configuration; CWE-319 Cleartext Transmission of Sensitive Information.
