import json
import re
from typing import Any, cast

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from api_checker.scanner.common import _openapi_31_or_later
from api_checker.scanner.references import pointer_fragment, pointer_join, resolve_local_ref

MAX_SPEC_BYTES = 16 * 1024 * 1024


class SpecError(ValueError):
    """The uploaded API definition could not be parsed or is unsupported."""


class DuplicateKeyError(ValueError):
    """A JSON or YAML object contains a duplicate key."""


_SafeLoaderBase = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class _UniqueKeySafeLoader(_SafeLoaderBase):  # type: ignore[valid-type, misc]
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, yaml.MappingNode):
            return cast(dict[Any, Any], super().construct_mapping(node, deep=deep))

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
        return cast(dict[Any, Any], super().construct_mapping(node, deep=deep))


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _parse_document(source: str, filename: str | None = None) -> Any:
    stripped = source.lstrip()
    is_json_file = isinstance(filename, str) and filename.lower().endswith(".json")
    is_yaml_file = isinstance(filename, str) and filename.lower().endswith((".yaml", ".yml"))
    if stripped.startswith(("{", "[")) and not is_yaml_file:
        try:
            return json.loads(source, object_pairs_hook=_unique_json_object)
        except json.JSONDecodeError:
            # A .json upload is expected to be JSON; do not feed a large
            # malformed JSON document through YAML's more permissive parser.
            if is_json_file:
                raise
            if len(source) > 256 * 1024:
                raise
            # JSON is also valid YAML. Let the YAML parser handle flow-style
            # documents that begin with a brace but are not strict JSON. Large
            # files without a YAML extension avoid a potentially slow fallback.
            pass
    return yaml.load(source, Loader=_UniqueKeySafeLoader)


def source_line_map(source: str) -> dict[str, int]:
    """Map JSON Pointer fragments to source lines for JSON and YAML inputs."""
    try:
        root = yaml.compose(source, Loader=_SafeLoaderBase)
    except yaml.YAMLError:
        return {}
    result: dict[str, int] = {}
    active_nodes: set[int] = set()
    visited = 0
    node_limit = 200_000

    def visit(node: yaml.Node, pointer: str) -> None:
        nonlocal visited
        if visited >= node_limit:
            return
        visited += 1
        result[pointer_fragment(pointer)] = node.start_mark.line + 1
        identity = id(node)
        if identity in active_nodes:
            return
        active_nodes.add(identity)
        if isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                if not isinstance(key_node, ScalarNode):
                    continue
                child_pointer = pointer_join(pointer, key_node.value)
                visit(value_node, child_pointer)
        elif isinstance(node, SequenceNode):
            for index, child in enumerate(node.value):
                visit(child, pointer_join(pointer, index))
        active_nodes.remove(identity)

    if root is not None:
        visit(root, "")
    return result


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


def parse_spec(source: str, filename: str | None = None) -> dict[str, Any]:
    if len(source.encode("utf-8")) > MAX_SPEC_BYTES:
        raise SpecError("Specifications are limited to 16 MB.")
    try:
        document = _parse_document(source, filename)
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
        raise SpecError(
            "Use either the OpenAPI 'openapi' version or Swagger 'swagger' version field, not both."
        )
    is_openapi_3 = (
        isinstance(version, str)
        and re.fullmatch(r"3\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version) is not None
    )
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

    return document
