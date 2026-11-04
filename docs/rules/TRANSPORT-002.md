# TRANSPORT-002 — Server template may allow cleartext transport

Flags a server URL template that permits HTTP or an unencrypted WebSocket
endpoint. It does not inspect the deployed server.

**Review:** constrain server variables to secure schemes and use `wss://` for
WebSockets that carry sensitive data.

**References:** OWASP API Security Top 10 API8:2023 Security Misconfiguration;
CWE-319 Cleartext Transmission of Sensitive Information.
