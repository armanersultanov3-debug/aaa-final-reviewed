# Changelog

All notable project changes are recorded here.

This project is still in the pre-1.0 stage. Public releases use `vX.Y.Z` Git
tags, and each released version must have a matching section in this file before
release artifacts are prepared.

## [Unreleased]

## [0.1.2] - 2026-06-16

- Add MIT license metadata, package classifiers, project URLs, README badges,
  contribution and security documents, GitHub issue templates, and a pull
  request template for public project presentation without changing analyzer
  behavior.

## [0.1.1] - 2026-06-16

- Add a schema-versioned packaged control-source coverage ledger, strict
  registry reconciliation, deterministic Markdown/JSON views, additive
  `coverage validate/show/export` commands, and release checks for document
  and package-artifact drift without increasing any coverage numerator.
- Add deterministic offline crosswalk validation, canonical OWASP/ASVS/PCI
  identifiers, and declared-versus-derived provenance in rule catalog and
  report JSON; conservatively correct ASVS, OWASP Top 10:2025, and PCI DSS
  coverage claims without changing detector behavior.
- Expand OpenAPI / Swagger external probes with common JSON schema paths and
  map Swagger/OpenAPI exposure to ASVS v5.0.0-13.4.5 partial documentation
  endpoint coverage.
- Expand dependency-manifest external probes with Java Maven/Gradle and
  .NET/NuGet manifest paths, and map the rule to ASVS v5.0.0-13.4.6 partial
  version-disclosure coverage.
- Add exposed Nginx, Apache HTTP Server, and Lighttpd configuration-file
  probes to the external safe-probe catalog.
- Add policy-gated `nginx.response_headers` control assessments with shared
  Nginx `add_header` / `add_header_inherit` semantics, a structured CSP AST,
  and route-manifest evaluation for CSP, Referrer-Policy, HSTS,
  `X-Content-Type-Options`, and COOP without changing canonical coverage
  percentages.
- Add declared endpoint/SNI TLS inventory analysis with a dedicated
  `analyze-tls-inventory` command, typed `external.tls_inventories` policy
  input, bounded TLS observation records, and follow-up-04-compatible native
  control assessment evidence without changing canonical coverage percentages.
- Correct the reviewed no-policy Nginx header edge cases called out by the
  follow-up design: location or `if in location` header replacement can now
  surface a missing CSP that was previously hidden, report-only CSP does not
  satisfy enforcement, and multiple enforcing CSP headers use conjunction
  semantics for unsafe-inline / unsafe-eval checks.
- Add application settings JSON exposure probes to the external safe-probe
  catalog.
- Document the TLS source-coverage explanation across NIST, PCI DSS, ISO/IEC
  27002, and FSTEC mappings.
- Add JavaScript source map exposure probes to the external safe-probe catalog.
- Expand dependency-manifest external probes with Python, Ruby, Go, and Rust
  project manifest and lockfile paths.
- Rework the project roadmap around source coverage from the pre-diploma
  benchmark and relevance sources.
- Expand the external safe-probe catalog with additional environment-file,
  database-dump, dependency-manifest, and archive path variants for existing
  catalog-backed rules.
- Document the standards-mapping health snapshot after the `v0.1.0` tag and
  pin the remaining mapping backlog to safe-probe catalog growth.
- Continue parser/effective-configuration precision work for the current
  four-server scope.
- Continue standards mapping, safe external probe growth, report explanation
  improvements, and release-readiness work.

## [0.1.0] - 2026-06-05

### Added

- Local static analyzers for Nginx, Apache HTTP Server, Lighttpd, and Microsoft
  IIS.
- External safe probing for HTTP, HTTPS, TLS, certificate, redirect, cookie,
  CORS, method, fingerprinting, and sensitive-path observations.
- Central rule registry with `list-rules`, rule metadata, standards mapping,
  and profile-based severity calibration.
- Text and JSON reports with stable finding fingerprints, standards grouping,
  and repeated-finding grouping.
- CI-oriented exit behavior through `--fail-on` and `--fail-on-new`.
- Suppression files with required reasons and expiry dates.
- Baseline creation and diff reporting for new, unchanged, resolved, and
  suppressed findings.
- Repository CI, optional Docker-backed integration checks, and a repeatable
  release check that builds and smoke-tests installed package artifacts.

### Documented

- Current project status, architecture, roadmap, severity methodology,
  standards coverage, CI integration, real-world-style fixture testing, and
  release preparation boundaries.
