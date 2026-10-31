from typing import Any

from app.scanner.common import HTTP_METHODS
from app.scanner.models import Finding
from app.scanner.references import resolve_local_ref


def check_transport(spec: dict[str, Any]) -> list[Finding]:
    insecure_urls: list[str] = []

    def collect_servers(servers: Any) -> None:
        if not isinstance(servers, list):
            return
        for server in servers:
            if (
                isinstance(server, dict)
                and isinstance(server.get("url"), str)
                and server["url"].lower().startswith("http://")
            ):
                insecure_urls.append(server["url"])

    collect_servers(spec.get("servers", []))
    collections = ["paths"]
    version = spec.get("openapi")
    try:
        if isinstance(version, str) and tuple(int(part) for part in version.split(".")[:2]) >= (3, 1):
            collections.append("webhooks")
    except ValueError:
        pass
    for collection_name in collections:
        items = spec.get(collection_name, {})
        if not isinstance(items, dict):
            continue
        for raw_path_item in items.values():
            path_item = resolve_local_ref(spec, raw_path_item)
            if not isinstance(path_item, dict):
                continue
            collect_servers(path_item.get("servers", []))
            for method in HTTP_METHODS:
                operation = path_item.get(method)
                if isinstance(operation, dict):
                    collect_servers(operation.get("servers", []))

    # Swagger 2.0 stores schemes and host/basePath separately.
    if spec.get("swagger") == "2.0":
        schemes = spec.get("schemes")
        if isinstance(schemes, list) and "http" in [str(item).lower() for item in schemes]:
            insecure_urls.append(f"http://{spec.get('host', '<host>')}{spec.get('basePath', '')}")

    if not insecure_urls:
        return []
    return [Finding(
        rule_id="TRANSPORT-001",
        title="The specification advertises an unencrypted HTTP server",
        severity="medium",
        confidence="high",
        summary="At least one declared server uses HTTP. The specification does not prove whether HTTPS is also configured or enforced.",
        impact="Traffic sent over plain HTTP can be read or modified by parties on the network path.",
        remediation="Prefer HTTPS for API traffic and redirect or reject plaintext HTTP at the service boundary.",
        evidence={"servers": sorted(set(insecure_urls))[:20]},
    )]
