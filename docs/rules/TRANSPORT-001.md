# TRANSPORT-001 — Plain HTTP server

Flags a declared server URL using HTTP. Local development endpoints may be
intentional, and the specification may not list every deployment endpoint.

**Review:** use HTTPS for production endpoints and redirect or reject cleartext
traffic at the edge.

**References:** OWASP API Security Top 10 API8:2023 Security Misconfiguration;
CWE-319 Cleartext Transmission of Sensitive Information.
