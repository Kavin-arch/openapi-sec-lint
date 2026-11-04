# RESOURCE-002 — Request or collection response lacks bounds

Flags request strings or maps without documented limits, or a top-level GET
array without a recognizable pagination parameter. This heuristic is low
severity and does not establish runtime resource exposure.

**Review:** set realistic input bounds, enforce them in the service, and
paginate large collection endpoints.

**References:** OWASP API Security Top 10 API4:2023 Unrestricted Resource
Consumption; CWE-400 Uncontrolled Resource Consumption.
