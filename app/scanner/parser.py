import json
import re
from typing import Any

import yaml

from app.scanner.references import resolve_local_ref


class SpecError(ValueError):
    """The uploaded API definition could not be parsed or is unsupported."""


class DuplicateKeyError(ValueError):
    """A JSON or YAML object contains a duplicate key."""


class _UniqueKeySafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict:
        if not isinstance(node, yaml.MappingNode):
            return super().construct_mapping(node, deep=deep)

        # Check explicit keys before flattening YAML merge keys. Explicit values
        # are allowed to override merged defaults, but duplicates in one mapping
        # are almost always accidental and otherwise silently overwrite data.
        explicit_keys: set[Any] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in explicit_keys:
                    raise DuplicateKeyError(f"Duplicate YAML key: {key!r}")
                explicit_keys.add(key)
            except TypeError as exc:
                raise DuplicateKeyError("YAML object keys must be scalar values.") from exc

        self.flatten_mapping(node)
        return super().construct_mapping(node, deep=deep)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _parse_document(source: str) -> Any:
    stripped = source.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            return json.loads(source, object_pairs_hook=_unique_json_object)
        except json.JSONDecodeError:
            # JSON is also valid YAML. Let the YAML parser handle flow-style
            # documents that begin with a brace but are not strict JSON.
            pass
    return yaml.load(source, Loader=_UniqueKeySafeLoader)


def _count_operations(spec: dict[str, Any], items: Any) -> int:
    if not isinstance(items, dict):
        return 0
    methods = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
    return sum(
        1
        for raw_path_item in items.values()
        for path_item in (resolve_local_ref(spec, raw_path_item),)
        if isinstance(path_item, dict)
        for method in methods
        if isinstance(path_item.get(method), dict)
    )


def _valid_security_requirements(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(requirement, dict)
        and all(
            isinstance(scheme, str)
            and isinstance(scopes, list)
            and all(isinstance(scope, str) for scope in scopes)
            for scheme, scopes in requirement.items()
        )
        for requirement in value
    )


def _openapi_31_or_later(version: Any) -> bool:
    if not isinstance(version, str):
        return False
    try:
        return tuple(int(part) for part in version.split(".")[:2]) >= (3, 1)
    except ValueError:
        return False


def _validate_operation_security(spec: dict[str, Any], items: dict[str, Any]) -> None:
    methods = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
    for raw_path_item in items.values():
        path_item = resolve_local_ref(spec, raw_path_item)
        if not isinstance(path_item, dict):
            continue
        for method in methods:
            operation = path_item.get(method)
            if (
                isinstance(operation, dict)
                and "security" in operation
                and not _valid_security_requirements(operation["security"])
            ):
                raise SpecError("Operation security fields must be arrays of Security Requirement Objects.")


def parse_spec(source: str) -> dict[str, Any]:
    try:
        document = _parse_document(source)
    except DuplicateKeyError as exc:
        raise SpecError("Could not parse the file: duplicate object key.") from exc
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise SpecError(f"Could not parse the file{location}.") from exc
    except RecursionError as exc:
        raise SpecError("Could not parse the file: the document is nested too deeply.") from exc

    if not isinstance(document, dict):
        raise SpecError("The API definition must be a JSON or YAML object.")

    version = document.get("openapi")
    swagger = document.get("swagger")
    if "openapi" in document and "swagger" in document:
        raise SpecError("Use either the OpenAPI 'openapi' version or Swagger 'swagger' version field, not both.")
    is_openapi_3 = isinstance(version, str) and re.fullmatch(r"3\.\d+\.\d+", version) is not None
    is_swagger_2 = swagger == "2.0"
    if not (is_openapi_3 or is_swagger_2):
        raise SpecError("Supported formats are OpenAPI 3.x and Swagger 2.0.")

    info = document.get("info")
    if (
        not isinstance(info, dict)
        or not isinstance(info.get("title"), str)
        or not info["title"].strip()
        or not isinstance(info.get("version"), str)
        or not info["version"].strip()
    ):
        raise SpecError("The API definition must include info.title and info.version.")

    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise SpecError("The 'paths' field must be an object.")
    webhooks = document.get("webhooks", {})
    if not isinstance(webhooks, dict):
        raise SpecError("The 'webhooks' field must be an object.")
    components = document.get("components", {})
    if not isinstance(components, dict):
        raise SpecError("The 'components' field must be an object.")

    if is_swagger_2 or (is_openapi_3 and not _openapi_31_or_later(version)):
        if "paths" not in document:
            raise SpecError("The API definition must include a 'paths' object.")
    if is_openapi_3 and _openapi_31_or_later(version):
        if not any(key in document for key in ("paths", "components", "webhooks")):
            raise SpecError("The API definition must include paths, components, or webhooks.")

    if "security" in document and not _valid_security_requirements(document["security"]):
        raise SpecError("The 'security' field must be an array of Security Requirement Objects.")
    _validate_operation_security(document, paths)
    if is_openapi_3 and _openapi_31_or_later(version):
        _validate_operation_security(document, webhooks)

    operation_count = _count_operations(document, paths)
    if is_openapi_3 and _openapi_31_or_later(version):
        operation_count += _count_operations(document, webhooks)
    if operation_count > 2_000:
        raise SpecError("This starter version accepts at most 2,000 operations per specification.")

    return document
