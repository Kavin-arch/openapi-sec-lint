# MASS-001 — Write schema may permit mass assignment

Flags write schemas that allow undeclared properties or include likely
server-managed fields without `readOnly`. The rule is low severity because a
schema cannot show how the server binds request fields.

**Review:** use explicit request models and enforce field-level authorization
and ownership in the service.

**References:** OWASP API Security Top 10 API3:2023 Broken Object Property
Level Authorization; CWE-915 Improperly Controlled Modification of
Dynamically-Determined Object Attributes.
