# BOLA-001 — Object identifier parameter

Flags integer or string path and query parameters whose names resemble object
IDs or UUIDs. Opaque IDs do not replace object-level authorization, and this
contract signal does not establish whether identifiers are guessable.

**Review:** test authorization for each object using another user's identifier.

**References:** OWASP API Security Top 10 API1:2023 Broken Object Level
Authorization; CWE-639 Authorization Bypass Through User-Controlled Key.
