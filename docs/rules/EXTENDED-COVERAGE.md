# Extended coverage checks

These checks add low-confidence contract review signals. They do not verify
runtime behavior.

| Rule | Trigger | Important limitation |
|---|---|---|
| `AUTH-004` | Admin or privileged-looking path/operation without declared authentication and role-like scopes | Names do not prove function-level authorization is missing. |
| `AUTH-005` | OAuth implicit or password flow in OpenAPI 3.x or Swagger 2.0 | Legacy clients may still document these flows intentionally. |
| `FLOW-001` | Write operation name/description resembles payment, transfer, invitation, vote, or similar sensitive flow | The rule cannot determine whether rate, replay, or eligibility controls exist. |
| `CONFIG-001` | Verbose-looking 5xx schema, wildcard request media type, or localhost/internal server URL | Schema text and addresses are hints; deployment behavior may differ. |
| `INV-001` | Deprecated operation or route under `/v1`, `/beta`, `/alpha`, or `/preview` | Versioned routes are often intentional and version number alone is not a defect. |
| `CONSUME-001` | Operation metadata suggests importing, fetching, or consuming partner/provider data | This is a workflow hint; it does not inspect upstream trust or response validation. |
| `CONTRACT-001` | Credential-like query/cookie parameter, absent 401/403/429 response, unbounded input string, missing password format, or multipart body | OpenAPI cannot express gateway byte limits portably; document them in deployment controls. |

`DATA-001` ignores common cursor, continuation, and pagination token field names
to reduce noise from tokens used only to traverse a collection.
