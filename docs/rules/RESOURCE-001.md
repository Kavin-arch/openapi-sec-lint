# RESOURCE-001 — Request array lacks a maximum size

Flags a request array without a documented `maxItems`. A contract limit is
useful but does not prove the server enforces the same bound.

**Review:** document a realistic maximum and enforce request-size and item
limits in the service.

**References:** OWASP API Security Top 10 API4:2023 Unrestricted Resource
Consumption; CWE-770 Allocation of Resources Without Limits or Throttling.
