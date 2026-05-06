# Roadmap 1 - Cross-Server Local Hardening Precision

## Scope

This is the current first-priority local-analysis roadmap. It covers rule
coverage that can be added with the existing parsers, AST/effective-config
models, and safe local fixtures. It intentionally avoids new external probing,
host-inspection, package/service checks, and parser rewrites.

## PR Slice 1: Cross-Server Request/Auth/Header Policy

Status: implemented.

1. HTTP method policy.
   - Nginx: `limit_except` and explicit method-policy checks are covered.
   - Apache: `Limit`, `LimitExcept`, and `Require method` style explicit
     allowlists are covered where the current AST can prove them.
   - Lighttpd: explicit dangerous-method policy coverage is present for
     TRACE, PUT, DELETE, CONNECT, PATCH, PROPFIND, and WebDAV-like methods.

2. Authentication over plain HTTP.
   - Apache and Lighttpd now flag Basic-auth style policy on non-TLS scopes.
   - IIS Basic/form-auth transport coupling is covered by the IIS XML policy
     rules.
   - Nginx remains covered indirectly by local TLS/auth policy checks and is a
     lower-priority follow-up if stricter `auth_basic` scope modeling is needed.

3. HSTS policy quality.
   - Nginx, Apache, Lighttpd, and IIS all have local weak
     `Strict-Transport-Security` value checks aligned with the shared policy.

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

Status: implemented.

- Curated deny-policy checks cover `.env`, VCS metadata, editor metadata,
  backup/temp artifacts, package manager config files, and common lockfiles.
- The checks stay conservative and scope-aware so redirect-only or
  non-content-serving blocks do not create header/path policy noise.

## PR Slice 5: Header Policy Quality

Status: implemented.

- Referrer-Policy: shared unsafe-value semantics for Nginx, Apache, and the
  normalized universal layer used by Lighttpd/IIS.
- Permissions-Policy: conservative unsafe checks for wildcard grants and empty
  ineffective policy values.
- X-Frame-Options and CSP `frame-ancestors`: missing-XFO rules now treat an
  unconditional CSP `frame-ancestors` policy as equivalent clickjacking
  control and keep conditional Apache CSP from hiding missing coverage.
- CSP: keep strictness improvements separate from broad CSP parsing claims.

## PR Slice 6: TLS Local Complements

Status: implemented.

- Added only direct, parseable TLS configuration complements that do not require
  a live handshake.
- Nginx: flags explicit `ssl_conf_command Options Compression` and
  `UnsafeLegacyRenegotiation`; intentionally does not treat
  `ssl_certificate_compression` as TLS record compression.
- Lighttpd: flags explicit `ssl.openssl.ssl-conf-cmd` TLS compression /
  unsafe-renegotiation options and disabled client-renegotiation mitigation.
- Keep runtime-only items such as certificate chain validation, negotiated
  forward secrecy, OCSP runtime behavior, ECH, and redirect corroboration for a
  separate external-safe roadmap.

## PR Slice 7: Apache Precision Without Parser Changes

Status: partially implemented; remaining work is a focused follow-up.

- `AllowOverride` baseline checks, timeout/keepalive value checks, redirect
  precision, and default TLS VirtualHost unknown-host rejection are present.
- Remaining direct-rule work: improve `Options` policy precision per directory
  class and refine broader non-TLS VirtualHost allowed-host precision.
- Deeper `Require` / module-inventory / ModSecurity semantics stay
  `parser-depth` and should not be forced into string-only checks.

## PR Slice 8: IIS XML Policy Completeness

Status: implemented.

- Authorization defaults now cover absent/empty IIS URL authorization policy,
  anonymous allow rules, inheritance, remove-only overrides, and affected
  `<location>` scopes.
- `system.web` policy checks cover `httpRuntime`, forms authentication,
  cookies, credentials, retail mode, trust level, and MachineKey posture where
  the effective XML model exposes the setting.
- `requestFiltering` policy checks cover double escaping, high-bit characters,
  URL/query/body limits, file-extension allow-unlisted defaults, and explicit
  native `Server` header removal disablement.
- App-pool checks cover explicit identity policy and cross-site shared pool
  usage where applicationHost data exposes the relevant attributes.

## Explicitly Out Of Scope

- External scanning expansion.
- Host package/service/user/file-permission inspection.
- New parser architecture.
- Live third-party target probing.
- Secret collection or real credentials in fixtures.
