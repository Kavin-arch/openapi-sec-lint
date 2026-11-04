# AUTH-003 — OAuth scopes need review

Flags OAuth flows without documented scopes or operations that select no
scopes. OpenAPI scope declarations do not demonstrate that the API checks
them.

**Review:** document the least-privilege scopes and enforce them at each
operation.

**References:** OWASP API Security Top 10 API2:2023 Broken Authentication and
API5:2023 Broken Function Level Authorization; CWE-862 Missing Authorization.
