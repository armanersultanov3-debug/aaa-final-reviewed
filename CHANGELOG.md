# Changelog

All notable project changes are recorded here.

This project is still in the pre-1.0 stage. Public releases use `vX.Y.Z` Git
tags, and each released version must have a matching section in this file before
release artifacts are prepared.

## [Unreleased]

- Add exposed Nginx, Apache HTTP Server, and Lighttpd configuration-file
  probes to the external safe-probe catalog.
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
