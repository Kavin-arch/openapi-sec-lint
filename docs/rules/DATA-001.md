# DATA-001 — Sensitive-looking response field

Flags response property names commonly associated with credentials or
personal data, including compound names such as `password_hash` and
`authToken`. It does not inspect values or access policy.

**Review:** omit secrets from responses and restrict sensitive data to callers
who need it.

**References:** OWASP API Security Top 10 API3:2023 Broken Object Property
Level Authorization; CWE-200 Exposure of Sensitive Information to an
Unauthorized Actor.
