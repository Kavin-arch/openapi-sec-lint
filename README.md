# OpenAPI Security Lint

A local-first security linter for OpenAPI 3.x and Swagger 2.0 specifications.
It analyzes the contract and stores web scan history in SQLite. **It does not
send requests to the API described by a specification.** Findings are review
signals, not confirmation of runtime vulnerabilities.

## Checks

| Rule | Signal | Default severity |
|---|---|---|
| `AUTH-001` | Operations without an effective documented security requirement | Medium |
| `AUTH-002` | Undefined security scheme references or Basic authentication paired with HTTP | Medium |
| `AUTH-003` | OAuth flows without documented scopes or operations selecting no scopes | Medium |
| `BOLA-001` | Integer or string object identifier parameters | Low |
| `MASS-001` | Write schemas that permit undeclared fields or omit `readOnly` on likely server-managed fields | Low |
| `TRANSPORT-001` | Declared plain HTTP servers | High |
| `TRANSPORT-002` | Server templates that permit HTTP or `ws://` | Medium |
| `DATA-001` | Sensitive-looking response field names | Medium |
| `RESOURCE-001` | Request arrays without `maxItems` | Medium |
| `RESOURCE-002` | Request strings/maps without bounds or top-level GET arrays without pagination | Low |
| `SSRF-001` | URL-like request fields without an enum or pattern constraint | Medium |

Read the [rule reference](docs/rules/README.md) for limitations and OWASP API
Top 10/CWE mappings. `MASS-001` and `RESOURCE-002` are low severity because
these contract signals are especially noisy. Use `--disable RULE-ID` to turn
off checks that do not fit your API.

Local JSON Pointer `$ref` references are followed; external references are
never fetched. Findings are emitted per location and include stable
fingerprints. `x-security-ignore: ["RULE-ID"]` on an operation suppresses that
rule for the operation; on a schema property it suppresses findings at that
property and below it.

## Install and run

Python 3.11 or 3.12 is supported. From the repository:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m uvicorn api_checker.main:app --reload
```

Open <http://127.0.0.1:8000>. The API documentation is at
<http://127.0.0.1:8000/docs>. macOS and Linux users can create a virtual
environment with `python3 -m venv .venv` and activate it with
`source .venv/bin/activate`.

The local server accepts `localhost`, `127.0.0.1`, and `::1` Host headers by
default. Set `API_CHECKER_ALLOWED_HOSTS` to a comma-separated allowlist if you
use a different local hostname. The app has no user accounts or authentication;
keep it bound to loopback unless you add deployment-specific access controls.

Scans run in an isolated subprocess with a 70-second hard timeout by default.
Set `API_CHECKER_SCAN_TIMEOUT` to change it. Schema traversal also stops after
100,000 visited nodes or 55 seconds. A failed scan can be deleted, including a
queued or running scan; scans left running by a process restart are marked
failed.

## CLI

The CLI runs without Uvicorn or SQLite. It accepts files, directories, and
standard input, including multiple inputs:

```powershell
openapi-sec-lint --version
openapi-sec-lint scan examples/sample-openapi.yaml --fail-on medium --format sarif
openapi-sec-lint scan specs/ --disable MASS-001 --output report.json
Get-Content .\api.yaml | openapi-sec-lint scan - --format md
```

Formats are `json`, `sarif`, and `md`. `--output PATH` writes the report to a
file. `--disable RULE-ID` may be repeated or accept comma-separated IDs. A TOML
config can set defaults:

```toml
format = "sarif"
fail_on = "high"
disable = ["MASS-001", "RESOURCE-002"]
```

Use `--baseline baseline.json` to report only new findings by fingerprint and
`--write-baseline baseline.json` to save the current finding set. Every input
is limited to 16 MiB, matching the web API limit.

## API

- `GET /health` — process status and registered rule count.
- `POST /api/v1/scans` — queue a scan. The JSON body contains `name` (optional),
  `target_url`, `filename`, and `spec_text`; `Content-Type: application/json`
  is required.
- `GET /api/v1/scans?limit=50` — list recent scans.
- `GET /api/v1/scans/{id}` — read status, summary, findings, and source SHA-256.
- `GET /api/v1/scans/{id}/export?format=sarif|json|md` — download a report.
- `DELETE /api/v1/scans/{id}` — delete a scan, cancelling it when queued/running.
- `DELETE /api/v1/scans` — clear history when no scans are queued or running.
- `GET /api/v1/sample-spec` — load the bundled sample for the UI.

Uploads are limited to 16 MiB. Duplicate JSON/YAML object keys and missing
required top-level metadata are rejected. Parsing is structural, not full
OpenAPI validation. The source specification is removed from SQLite after
analysis; its SHA-256, report, and metadata remain in `data/scanner.sqlite3`.

Set `API_VULN_DB` to store SQLite elsewhere:

```powershell
$env:API_VULN_DB = "D:\api-checker-data\scanner.sqlite3"
python -m uvicorn api_checker.main:app --reload
```

## Docker

Build and run the non-root container with persistent history:

```powershell
docker build -t openapi-sec-lint .
docker run --rm -p 127.0.0.1:8000:8000 -v api-checker-data:/app/data openapi-sec-lint
```

The image uses a pinned Python base image and includes a `/health` health check.

## Development

Install development dependencies and run the same checks as CI:

```sh
python -m pip install -e ".[dev]"
ruff check api_checker tests
mypy api_checker
pytest --cov=api_checker --cov-fail-under=60
pip-audit
bandit -r api_checker
```

GitHub Actions runs the quality checks on Python 3.11 and 3.12, dogfoods the
bundled sample and regression corpus, and builds the Docker image. See the
[recorded corpus counts](docs/corpus-results.md). Dependabot checks Python and
workflow dependencies weekly. Version tags trigger a PyPI trusted-publishing
workflow; the package must be configured on PyPI before that workflow can
publish.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[CHANGELOG.md](CHANGELOG.md).

## Boundaries

- This is a specification linter, not a scanner of running APIs.
- The worker is a single-process, SQLite-backed local queue. Up to 10 scans may
  be queued or running at once.
- No live probes, credentials, rate-limit tests, or request/response captures
  are used or retained.
- The local server has no user accounts. Add authentication, authorization,
  retention controls, and deployment hardening before exposing it to remote
  users.
