import json
import re
from datetime import date
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote, urlsplit

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from api_checker.scanner.common import _openapi_31_or_later
from api_checker.scanner.references import pointer_fragment, pointer_join, resolve_local_ref

MAX_SPEC_BYTES = 16 * 1024 * 1024
MAX_REFERENCE_FILES = 100
MAX_REFERENCE_BYTES = 64 * 1024 * 1024


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
    # This custom loader is based on SafeLoader and rejects Python object tags.
    return yaml.load(source, Loader=_UniqueKeySafeLoader)  # nosec B506


def _reference_pointer(relative_path: str) -> str:
    return pointer_join("/x-security-lint-ref-documents", relative_path)


def _bundle_file_references(
    document: dict[str, Any], source_path: Path | None, reference_root: Path | None
) -> dict[str, Any]:
    """Bundle relative file references below the top-level spec directory."""
    external_documents: dict[str, Any] = {}
    processed: set[str] = set()
    total_bytes = 0
    root_dir = reference_root.resolve() if reference_root is not None else None

    def document_key(path: Path) -> str:
        if root_dir is None:
            raise SpecError("Relative file references require scanning a file from the CLI.")
        return path.relative_to(root_dir).as_posix()

    def resolve_file(reference: str, current_path: Path | None) -> tuple[Path, str]:
        parsed = urlsplit(reference)
        if parsed.scheme or parsed.netloc or parsed.query:
            raise SpecError("Only relative local-file $ref values are supported.")
        decoded_path = unquote(parsed.path)
        if not decoded_path or "\\" in decoded_path or Path(decoded_path).is_absolute():
            raise SpecError("File references must use relative paths under the top-level spec directory.")
        if root_dir is None or source_path is None:
            raise SpecError("Relative file references require scanning a file from the CLI.")
        parent = current_path.parent if current_path is not None else root_dir
        try:
            resolved_path = (parent / decoded_path).resolve(strict=True)
            resolved_path.relative_to(root_dir)
        except (OSError, ValueError) as exc:
            raise SpecError("A referenced file is missing or escapes the top-level spec directory.") from exc
        if not resolved_path.is_file():
            raise SpecError("A referenced file is not a regular file.")
        return resolved_path, parsed.fragment

    def ensure_document(path: Path) -> str:
        nonlocal total_bytes
        key = document_key(path)
        if key in external_documents:
            return key
        if len(external_documents) >= MAX_REFERENCE_FILES:
            raise SpecError(f"A spec may reference at most {MAX_REFERENCE_FILES} external files.")
        try:
            raw_bytes = path.read_bytes()
        except OSError as exc:
            raise SpecError("A referenced file could not be read.") from exc
        total_bytes += len(raw_bytes)
        if total_bytes > MAX_REFERENCE_BYTES:
            raise SpecError("The total size of referenced files exceeds 64 MiB.")
        try:
            source = raw_bytes.decode("utf-8-sig")
            parsed = _parse_document(source, path.name)
        except (UnicodeError, DuplicateKeyError, json.JSONDecodeError, yaml.YAMLError, RecursionError) as exc:
            raise SpecError(f"Could not parse referenced file '{key}'.") from exc
        if not isinstance(parsed, dict | list):
            raise SpecError(f"Referenced file '{key}' must contain an object or array.")
        external_documents[key] = parsed
        return key

    def rewrite(value: Any, current_path: Path | None) -> None:
        if isinstance(value, dict):
            reference = value.get("$ref")
            if isinstance(reference, str):
                if current_path is None and not reference.startswith("#"):
                    target_path, fragment = resolve_file(reference, current_path)
                    key = ensure_document(target_path)
                    value["$ref"] = f"#{_reference_pointer(key)}"
                    if fragment:
                        value["$ref"] += f"/{fragment.lstrip('/')}"
                elif current_path is not None:
                    if reference.startswith("#"):
                        value["$ref"] = f"#{_reference_pointer(document_key(current_path))}{reference[1:]}"
                    else:
                        target_path, fragment = resolve_file(reference, current_path)
                        key = ensure_document(target_path)
                        value["$ref"] = f"#{_reference_pointer(key)}"
                        if fragment:
                            value["$ref"] += f"/{fragment.lstrip('/')}"
            for child in value.values():
                rewrite(child, current_path)
        elif isinstance(value, list):
            for child in value:
                rewrite(child, current_path)

    rewrite(document, None)
    while True:
        pending = [key for key in external_documents if key not in processed]
        if not pending:
            break
        for key in pending:
            processed.add(key)
            rewrite(external_documents[key], root_dir / Path(key) if root_dir is not None else None)
    if external_documents:
        document["x-security-lint-ref-documents"] = external_documents
    return document


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


def _validate_suppression_records(document: dict[str, Any]) -> None:
    pending: list[Any] = [document]
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            identity = id(value)
            if identity in seen:
                continue
            seen.add(identity)
            if "x-security-ignore" in value:
                records = value["x-security-ignore"]
                if not isinstance(records, list) or not records:
                    raise SpecError("x-security-ignore must be a non-empty list of suppression records.")
                for record in records:
                    if not isinstance(record, dict):
                        raise SpecError("Each x-security-ignore record must be an object.")
                    rule_id = record.get("rule_id")
                    reason = record.get("reason")
                    expires = record.get("expires")
                    if not isinstance(rule_id, str) or not re.fullmatch(r"[A-Z][A-Z0-9]+-\d{3}", rule_id):
                        raise SpecError("Each suppression record requires a valid rule_id.")
                    if not isinstance(reason, str) or not reason.strip():
                        raise SpecError("Each suppression record requires a non-empty reason.")
                    if expires is not None:
                        if type(expires) is not date:
                            if not isinstance(expires, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires):
                                raise SpecError("Suppression expires must be an ISO date (YYYY-MM-DD).")
                            try:
                                date.fromisoformat(expires)
                            except ValueError as exc:
                                raise SpecError("Suppression expires must be an ISO date (YYYY-MM-DD).") from exc
                    if set(record) - {"rule_id", "reason", "expires"}:
                        raise SpecError("Suppression records may contain only rule_id, reason, and expires.")
            pending.extend(value.values())
        elif isinstance(value, list):
            identity = id(value)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend(value)


def parse_spec(
    source: str,
    filename: str | None = None,
    *,
    source_path: str | Path | None = None,
    reference_root: str | Path | None = None,
) -> dict[str, Any]:
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

    document = _bundle_file_references(
        document,
        Path(source_path) if source_path is not None else None,
        Path(reference_root) if reference_root is not None else None,
    )
    _validate_suppression_records(document)

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
