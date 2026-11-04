# Changelog

## 0.3.0 — 2026-11-04

- Bound schema traversal by node count and elapsed time, and moved analysis into
  a subprocess that the worker can terminate on timeout.
- Mark interrupted scans as failed and allow queued or running scans to be
  deleted from the interface.
- Renamed the import package to `api_checker`, packaged the static UI and sample,
  and aligned runtime version reporting with installed package metadata.
- Added JSON content-type enforcement, trusted-host validation, and browser
  security headers.
- Added per-location finding fingerprints, richer SARIF metadata and source
  regions, and expanded CLI input, configuration, and baseline features.
- Added an MIT license and contributor and security policies.
