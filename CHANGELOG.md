# Changelog

## Unreleased

- Made the CLI install independent of the optional web server dependencies.
- Added HTML, GitHub Actions annotation, and JUnit reports, report schema,
  project configuration discovery, rule severity overrides, and path ignores.
- Added a composite GitHub Action, pre-commit hook, GHCR publishing, signed
  release artifacts, SPDX SBOM generation, and OpenSSF Scorecard reporting.
- Documented the architecture and threat model; grouped UI findings by rule,
  added highlighted source-line excerpts, and scan history comparison.
- Added the terminal demo and social preview assets, comparison and CI examples,
  issue and pull request templates, a code of conduct, and starter issue labels.

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
