# AUTH-001 — Operations without documented security

Flags an operation that has no effective OpenAPI security requirement. This
may be intentional for a public operation, and documented security does not
prove the service enforces it.

**Review:** verify the operation's intended audience and the deployed
authentication and authorization controls.

**References:** OWASP API Security Top 10 API2:2023 Broken Authentication;
CWE-306 Missing Authentication for Critical Function; CWE-862 Missing
Authorization.
