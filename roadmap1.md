# Roadmap 1 - Cross-Server Local Hardening Precision

## Scope

This is the current first-priority local-analysis roadmap. It covers rule
coverage that can be added with the existing parsers, AST/effective-config
models, and safe local fixtures. It intentionally avoids new external probing,
host-inspection, package/service checks, and parser rewrites.

## PR Slice 1: Cross-Server Request/Auth/Header Policy

Status: in progress.

1. HTTP method policy.
   - Nginx: keep hardening method policy coverage around `limit_except` and
     request-method policy patterns.
   - Apache: keep hardening `Limit`, `LimitExcept`, and `Require method`
     coverage.
   - Lighttpd: add local detection for explicit unsafe request-method policies,
     especially TRACE, PUT, DELETE, CONNECT, PATCH, PROPFIND, and WebDAV-like
     methods.

2. Authentication over plain HTTP.
   - Nginx: flag active `auth_basic` on non-TLS, non-redirect content scopes.
   - Apache: flag `AuthType Basic` on non-TLS scopes.
   - Lighttpd: flag `auth.require` / Basic-auth style policy when SSL is not
     enabled for the analyzed scope.

3. HSTS policy quality.
   - Nginx: flag weak `Strict-Transport-Security` values on TLS servers.
   - Apache: keep the existing missing/unsafe HSTS checks and align quality
     semantics with the shared policy.
   - Lighttpd: flag weak `Strict-Transport-Security` values configured through
     `setenv.add-response-header`.
   - IIS: flag weak `Strict-Transport-Security` custom header values.

## PR Slice 2: Request, Body, and Header Limits

Status: implemented.

- Nginx: added conservative too-large checks for `client_max_body_size`,
  `client_header_buffer_size`, and `large_client_header_buffers`; `0` body-size
  detection now follows last-directive semantics inside each scope.
- Apache: no new rule was needed; current `LimitRequest*` checks already use
  effective scope, redirect-only suppression, and benchmark thresholds.
- IIS: `fileExtensions` now treats missing/default `allowUnlisted` under an
  explicit `requestFiltering` policy as unsafe while leaving safe
  `maxUrl` / `maxQueryString` IIS defaults silent.
- Lighttpd: keep `server.max-request-size` and `server.max-connections`
  coverage precise with conditional/effective scope tests.

## PR Slice 3: Logging Quality

Status: implemented.

- Nginx and Apache: deepened log-format quality checks for stable security
  fields such as timestamp, client address, authenticated user, request line,
  status, user-agent, request ID, forwarded chain, TLS protocol/cipher, and
  upstream/request timing where applicable.
- Lighttpd: added minimal `accesslog.format` field-quality checks when the
  existing effective model exposes the format safely.

## PR Slice 4: Sensitive Paths and Extension Deny Policy

Status: planned.

- Add curated deny-policy checks for `.env`, VCS metadata, editor metadata,
  backup/temp artifacts, package manager config files, and common lockfiles.
- Keep these checks conservative and scope-aware so redirect-only or
  non-content-serving blocks are not noisy.

## PR Slice 5: Header Policy Quality

Status: planned.

- Referrer-Policy: unsafe values across all local analyzers.
- Permissions-Policy: dangerous directives, wildcards, or empty ineffective
  policy where parseable.
- X-Frame-Options and CSP `frame-ancestors`: avoid duplicate noise when one
  control safely covers the other.
- CSP: keep strictness improvements separate from broad CSP parsing claims.

## PR Slice 6: TLS Local Complements

Status: planned.

- Add only direct, parseable TLS configuration complements that do not require a
  live handshake.
- Keep runtime-only items such as certificate chain validation, negotiated
  forward secrecy, OCSP runtime behavior, ECH, and redirect corroboration for a
  separate external-safe roadmap.

## PR Slice 7: Apache Precision Without Parser Changes

Status: planned.

- Improve `Options` policy precision per directory class.
- Refine non-TLS VirtualHost allowed-host precision.
- Tune `AllowOverride` and timeout noise only where current effective helpers
  can prove the inherited/default outcome.

## PR Slice 8: IIS XML Policy Completeness

Status: planned.

- Authorization defaults.
- `system.web` absence/default policy.
- requestFiltering absence/default policy.
- App pool default materialization where available in the current effective
  model.

## Explicitly Out Of Scope

- External scanning expansion.
- Host package/service/user/file-permission inspection.
- New parser architecture.
- Live third-party target probing.
- Secret collection or real credentials in fixtures.
