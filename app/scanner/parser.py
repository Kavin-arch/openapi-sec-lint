import json
from typing import Any

import yaml


class SpecError(ValueError):
    """The uploaded API definition could not be parsed or is unsupported."""


def parse_spec(source: str) -> dict[str, Any]:
    try:
        document = json.loads(source) if source.lstrip().startswith(("{", "[")) else yaml.safe_load(source)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise SpecError(f"Could not parse the file: {exc}") from exc

    if not isinstance(document, dict):
        raise SpecError("The API definition must be a JSON or YAML object.")

    version = document.get("openapi")
    swagger = document.get("swagger")
    if not (isinstance(version, str) and version.startswith("3.")) and swagger != "2.0":
        raise SpecError("Supported formats are OpenAPI 3.x and Swagger 2.0.")

    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise SpecError("The 'paths' field must be an object.")

    operation_count = sum(
        1
        for path_item in paths.values()
        if isinstance(path_item, dict)
        for method in ("get", "post", "put", "patch", "delete", "options", "head", "trace")
        if isinstance(path_item.get(method), dict)
    )
    if operation_count > 2_000:
        raise SpecError("This starter version accepts at most 2,000 operations per specification.")

    return document
