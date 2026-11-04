# SSRF-001 — URL-like request field lacks a constraint

Flags request fields that look like URLs but have no schema `enum` or `pattern`
constraint. Schema constraints alone do not prevent server-side request
forgery.

**Review:** allowlist destinations and schemes, validate resolved IP addresses,
and enforce outbound network controls in the service.

**References:** OWASP API Security Top 10 API7:2023 Server Side Request Forgery;
CWE-918 Server-Side Request Forgery (SSRF).
