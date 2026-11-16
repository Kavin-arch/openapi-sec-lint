# Threat model

## Scope and assets

The tool accepts untrusted OpenAPI and Swagger documents. Assets include host CPU and memory, local files reachable through references, SQLite scan history, and the integrity of rendered reports. The web UI is intended for a single local operator and has no account or authorization layer.

## Threats and controls

| Threat | Controls | Remaining limit |
|---|---|---|
| Hostile specs consume CPU or memory | 16 MiB root spec limit, isolated subprocess, 70-second timeout, traversal time/node budgets, 10,000-finding cap | Python parsing still uses resources before the traversal budget begins; run untrusted workloads in a constrained environment |
| YAML alias bombs or recursive structures | Safe YAML loader, bounded document size, cycle-aware and memoized traversal | Parser behavior can change with dependency updates |
| Local reference path traversal | Relative refs are confined to the root directory; parent and symlink escapes rejected; file count and aggregate bytes capped | The CLI intentionally reads permitted local referenced files |
| UI cross-site scripting | Dynamic text is escaped before HTML insertion; snippets are escaped; API filenames are reduced to basenames | Treat any future HTML rendering or template change as a security boundary |
| Sensitive text remains in history | Full specification is deleted after analysis; only the single flagged source line (capped at 500 characters) is retained with each location; scan deletion removes report data | The excerpt can contain secrets on the reported line; protect the local database and clear history when appropriate |
| Unsafe target URL causes outbound access | Target URL is metadata only and is never fetched | Do not infer live API behavior from contract-only results |

## Trust boundaries

1. The input file or browser upload is untrusted.
2. The parser and rules execute in a child process with bounded inputs and runtime.
3. The web parent accepts a structured child-process result and stores findings in SQLite.
4. The browser receives report JSON and renders escaped strings; do not serve this unauthenticated app on an untrusted network.

