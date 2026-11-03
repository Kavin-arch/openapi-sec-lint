from app.scanner.common import _walk_schema
from app.scanner.references import pointer_fragment, resolve_local_ref


def test_escaped_pointer_tokens_and_percent_encoded_fragment():
    spec = {"components": {"schemas": {"a/b~c": {"type": "string"}, "c%d": 3}}}
    assert resolve_local_ref(spec, {"$ref": "#/components/schemas/a~1b~0c"}) == {"type": "string"}
    assert resolve_local_ref(spec, {"$ref": "#/components/schemas/c%25d"}) == 3


def test_fragment_percent_decoding_precedes_pointer_token_splitting():
    spec = {"foo": {"bar": "nested"}, "foo/bar": "single"}
    assert resolve_local_ref(spec, {"$ref": "#/foo%2Fbar"}) == "nested"
    assert resolve_local_ref(spec, {"$ref": "#/foo~1bar"}) == "single"


def test_pointer_fragments_encode_uri_unsafe_property_characters():
    spec = {"a b": {"#%": "value"}}
    assert pointer_fragment("/a b/#%") == "#/a%20b/%23%25"
    assert resolve_local_ref(spec, {"$ref": "#/a%20b/%23%25"}) == "value"


def test_negative_array_index_is_rejected():
    reference = {"$ref": "#/items/-1"}
    assert resolve_local_ref({"items": ["first", "last"]}, reference) == reference


def test_integer_yaml_mapping_key_fallback():
    spec = {"responses": {200: {"description": "ok"}}}
    assert resolve_local_ref(spec, {"$ref": "#/responses/200"}) == {"description": "ok"}


def test_circular_local_refs_terminate():
    spec = {
        "components": {
            "schemas": {"A": {"$ref": "#/components/schemas/B"}, "B": {"$ref": "#/components/schemas/A"}}
        }
    }
    resolved = resolve_local_ref(spec, {"$ref": "#/components/schemas/A"})
    assert isinstance(resolved, dict)


def test_openapi_31_schema_ref_siblings_are_preserved():
    spec = {
        "openapi": "3.1.0",
        "components": {"schemas": {"items": {"type": "array", "items": {"type": "string"}}}},
    }
    root = {"$ref": "#/components/schemas/items", "maxItems": 50, "writeOnly": True}
    nodes = list(_walk_schema(spec, root))
    assert nodes[0][1]["maxItems"] == 50
    assert nodes[0][1]["writeOnly"] is True


def test_openapi_30_reference_object_siblings_are_not_merged():
    spec = {
        "openapi": "3.0.3",
        "components": {"schemas": {"items": {"type": "array"}}},
    }
    nodes = list(_walk_schema(spec, {"$ref": "#/components/schemas/items", "maxItems": 50}))
    assert "maxItems" not in nodes[0][1]


def test_root_combinator_trails_have_no_leading_dot():
    spec = {"openapi": "3.1.0"}
    nodes = list(_walk_schema(spec, {"allOf": [{"properties": {"tags": {"type": "array"}}}]}))
    assert "allOf[0].tags" in [trail for trail, _ in nodes]
