# API Vulnerability Checker

A local-first static reviewer for OpenAPI 3.x and Swagger 2.0 specifications. It parses JSON or YAML, runs contract checks, and stores scan history in SQLite. **It does not send requests to the target API.** Findings are review signals, not confirmation of runtime vulnerabilities.

## Checks

| Rule | Signal |
|---|---|
| `AUTH-001` | Operations without an effective documented security requirement |
| `AUTH-002` | Undefined security scheme references or HTTP Basic paired with a declared HTTP server |
| `AUTH-003` | OAuth flows without documented scopes or operations selecting no scopes |
| `BOLA-001` | Identifier-like integer parameters for manual object-authorization review |
| `MASS-001` | Write schemas that permit undeclared fields or omit `readOnly` on likely server-managed fields |
| `TRANSPORT-001` | Declared plain HTTP servers |
| `TRANSPORT-002` | Server templates that permit HTTP or unencrypted `ws://` servers |
| `DATA-001` | Sensitive-looking response field names |
| `RESOURCE-001` | Request arrays without documented `maxItems` |
| `RESOURCE-002` | Request strings/maps without documented limits or top-level GET arrays without pagination parameters |
| `SSRF-001` | URL-like request fields without a schema enum or pattern constraint |

Several checks are deliberately heuristic. In particular, identifier shapes do not prove BOLA, schema flags do not prove server behavior, and missing URL constraints do not prove SSRF. Review findings against the implementation and its runtime controls.

Local JSON Pointer `$ref` references are followed; external references are never fetched. Findings include JSON Pointer locations. `x-security-ignore: ["RULE-ID"]` on an operation suppresses that rule for the operation; on a schema property it suppresses findings at that property and below it.

## Run locally

Python 3.11 or 3.12 is supported. From PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. The API documentation is at <http://127.0.0.1:8000/docs>. macOS and Linux users can create a virtual environment with `python3 -m venv .venv` and activate it with `source .venv/bin/activate`.

The app is intended for local use. Keep it bound to `127.0.0.1`; it does not include accounts or authentication.

## CLI

The CLI runs the scanner directly without starting Uvicorn or using SQLite:

```powershell
python -m app.cli scan examples/sample-openapi.yaml --fail-on medium --format sarif
```

Install the project to get the `api-checker` command. Formats are `json`, `sarif`, and `md`. `--fail-on` returns exit code 1 when a finding at that severity or higher is present.

## Try the sample

Use **Try Sample Spec** in the upload form to load `examples/sample-openapi.yaml` without browsing for it.

## API

- `GET /health` — process status and registered check count.
- `POST /api/v1/scans` — queue a scan. The JSON body contains `name` (optional), `target_url`, `filename`, and `spec_text`.
- `GET /api/v1/scans?limit=50` — list recent scans.
- `GET /api/v1/scans/{id}` — read status, summary, findings, and the source SHA-256 fingerprint.
- `GET /api/v1/scans/{id}/export?format=sarif|json|md` — download a report.
- `DELETE /api/v1/scans/{id}` — delete a completed or failed scan.
- `DELETE /api/v1/scans` — clear history when no scans are queued or running.
- `GET /api/v1/sample-spec` — load the bundled sample for the UI.

Uploads are limited to 2 MB and 2,000 operations, including OpenAPI 3.1+ webhooks. Duplicate JSON/YAML object keys and missing required top-level metadata are rejected. This is structural parsing, not full OpenAPI validation. The source specification is removed from SQLite after analysis; its SHA-256, report, and metadata remain in `data/scanner.sqlite3`.

Set `API_VULN_DB` to store the SQLite file elsewhere:

```powershell
$env:API_VULN_DB = "D:\api-checker-data\scanner.sqlite3"
python -m uvicorn app.main:app --reload
```

## Docker

Build and run the non-root container with a persistent named volume for SQLite history:

```powershell
docker build -t api-vulnerability-checker .
docker run --rm -p 127.0.0.1:8000:8000 -v api-checker-data:/app/data api-vulnerability-checker
```

## Development and CI

The optional `dev` dependencies include pytest, pytest-cov, Ruff, and mypy. Run checks locally with:

```powershell
ruff check app tests
mypy app
pytest --cov=app --cov-report=term-missing
```

GitHub Actions runs these checks on Python 3.11 and 3.12 for pushes and pull requests.

## Current boundaries

- The worker is an in-process single-worker queue backed by SQLite. Queued jobs survive restart; running jobs are requeued at startup.
- The local queue accepts at most 10 queued or running scans.
- There are no live probes, credentials, rate-limit tests, injection payloads, or runtime header checks.
- No full request/response captures are retained.
- Before serving remote users, add authentication and authorization, retention controls, scan cancellation, rate limits, worker and storage hardening, and an operational queue/database design suitable for the deployment.
