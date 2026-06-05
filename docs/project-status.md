# Project Status

Snapshot date: 2026-06-05.

This document records the state of the project after the pre-graduation
practice milestone. It is intentionally short: detailed rule mappings, test
reports, and standards planning remain in the dedicated documents linked below.

## Current scope

The project ships a Python CLI for security review of web server
configurations. It has two independent analysis modes:

- local static analysis of configuration files;
- external safe probing of a running HTTP/HTTPS endpoint.

Local analysis currently supports:

- Nginx;
- Apache HTTP Server;
- Lighttpd;
- Microsoft IIS.

External probing is server-agnostic and enriches results with HTTP, HTTPS, TLS,
certificate, redirect, cookie, CORS, method, fingerprinting, and safe
sensitive-path observations.

## Implemented capabilities

The current implementation includes:

- server-specific parsers, include handling, and effective-configuration
  helpers where needed;
- a shared normalized model for universal cross-server rules;
- a centralized rule registry and `list-rules` inventory output;
- profile-based severity calibration;
- text and JSON reports;
- standards grouping and repeated-finding grouping;
- stable fingerprints for CI, suppressions, and baseline comparison;
- `--fail-on`, `--fail-on-new`, suppression files, and baseline/diff reporting;
- repository CI plus optional Docker-backed integration tests;
- a repeatable release-preparation flow with `CHANGELOG.md`, a manual release
  check workflow, version/tag guidance, and installed-package smoke checks.

The rule inventory is documented in [rule-coverage.md](rule-coverage.md). The
severity model is documented in
[severity-methodology.md](severity-methodology.md).

## Validation status

The project has automated tests for:

- CLI behavior;
- report formatting;
- rule registry integrity;
- standards helpers and standards grouping;
- suppression and baseline behavior;
- local analyzers for Nginx, Apache, Lighttpd, and IIS;
- external HTTP/TLS probing;
- Docker-backed integration slices;
- documentation/rule inventory drift.

The test strategy and public-source-derived configuration corpus are documented
in [testing-real-world-configs.md](testing-real-world-configs.md) and
[public-config-real-world-testing-report-2026-05-15.md](public-config-real-world-testing-report-2026-05-15.md).

## Known boundaries

The tool is not a full penetration-testing scanner and does not attempt active
exploitation. External probing is limited to safe, non-mutating checks.

The tool also does not claim full application-security coverage. It can observe
web-server configuration, selected inherited/effective configuration state, and
runtime HTTP/TLS signals; application code, business authorization logic, host
hardening, package inventory, and SIEM policy remain outside the default scope
unless a specific rule has a reliable signal.

Known scope limits are tracked in [rule-coverage.md](rule-coverage.md) and
[standards-roadmap.md](standards-roadmap.md).

## Immediate next work

The next development phase should focus on the work already promised for the
graduation project:

1. keep parser and effective-configuration models aligned with real server
   behavior;
2. continue standards-driven rule and mapping work;
3. strengthen the external safe-probe catalog;
4. reduce false positives and improve report explanations;
5. continue release hardening by deciding when public package publishing becomes
   useful, while keeping the current tag-based release workflow repeatable.

Future server-family expansion should be handled as a separate research and
planning track, after the current four-server core and release workflow are
stable.
