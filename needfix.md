# Needfix

Confirmed analyzer precision issues moved out of `docs/roadmap.md` on
2026-05-04. These are not offensive findings; they are correctness and report
quality bugs in static configuration analysis.

## Resolution Status

Implemented in the repository (originally tracked on
`codex/fix-effective-scope-semantics`):

- Fixed the confirmed Nginx inherited/effective directive bugs for access logs,
  error logs, rate/connection limits, inherited security headers, and inherited
  TLS ciphers.
- Kept the already-fixed Nginx last-wins coverage for
  `ssl_prefer_server_ciphers`, stapling resolver/verify, and HTTP/2, and added
  the related inherited-policy regression coverage where it was missing.
- Fixed Lighttpd missing logging/header rules so host-conditional directives no
  longer suppress findings for unrelated hosts or the default no-host analysis.
- Fixed IIS cross-file effective-config merging so inherited child collections
  are merged with `add` / `remove` / `clear` semantics instead of being replaced.
- Added Apache `Options Indexes -Indexes` and `Options -Indexes Indexes`
  regression coverage for both rule output and normalized output.

Remaining backlog:

- (closed by `dfaf9b8` — "Add effective-cause grouping") Generic
  report-level grouping of repeated same-rule advice across many scopes is now
  implemented as the `--group-by-cause` formatter mode and the
  `Finding.effective_cause_key` opt-in field on the models. No remaining
  needfix backlog items at this time.

## Nginx Effective Configuration

Root problem: several Nginx rules inspect only direct `server` children or use
`any(on)` for repeated directives instead of resolving the effective
`main -> http -> server -> location` value.

Fix direction:

- Add a shared effective-context helper for Nginx directive lookups.
- Preserve last-wins behavior for scalar repeated directives.
- Preserve parent inheritance where Nginx inherits the directive from `http`
  into `server` or from `server` into `location`.
- Add regression fixtures for inherited parent values and repeated
  `on; off;` / `off; on;` cases.

Confirmed issues:

1. `nginx.missing_access_log`
   - File: `src/webconf_audit/local/nginx/rules/missing_access_log.py`
   - Problem: `http { access_log ...; server { ... } }` still emits one
     missing-access-log finding per server.

2. `nginx.missing_error_log`
   - File: `src/webconf_audit/local/nginx/rules/missing_error_log.py`
   - Problem: inherited `http`-level `error_log` is ignored, producing noisy
     duplicate server findings.

3. `nginx.missing_limit_req` and `nginx.missing_limit_conn`
   - Files:
     `src/webconf_audit/local/nginx/rules/missing_limit_req.py`,
     `src/webconf_audit/local/nginx/rules/missing_limit_conn.py`
   - Problem: `limit_req` / `limit_conn` in `http` scope are not treated as
     inherited effective policy.

4. Nginx `add_header` based security-header rules
   - File: `src/webconf_audit/local/nginx/rules/header_utils.py`
   - Affected examples: CSP, HSTS, X-Frame-Options,
     X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
   - Problem: headers inherited from `http` are missed when the `server` block
     has no direct `add_header`.

5. `nginx.missing_ssl_ciphers` and
   `nginx.missing_ssl_prefer_server_ciphers`
   - Files:
     `src/webconf_audit/local/nginx/rules/missing_ssl_ciphers.py`,
     `src/webconf_audit/local/nginx/rules/missing_ssl_prefer_server_ciphers.py`
   - Problem: inherited TLS cipher settings are missed, and repeated
     `ssl_prefer_server_ciphers on; off;` can be interpreted incorrectly.

6. `nginx.ssl_stapling_missing_resolver` and
   `nginx.ssl_stapling_without_verify`
   - Files:
     `src/webconf_audit/local/nginx/rules/ssl_stapling_missing_resolver.py`,
     `src/webconf_audit/local/nginx/rules/ssl_stapling_without_verify.py`
   - Problem: inherited `ssl_stapling`, `ssl_stapling_verify`, and `resolver`
     state is not resolved consistently; repeated stapling values can create
     false positives or false negatives.

7. `nginx.missing_http2_on_tls_listener`
   - File:
     `src/webconf_audit/local/nginx/rules/missing_http2_on_tls_listener.py`
   - Problem: inherited `http2 on` is ignored, while direct
     `http2 on; http2 off;` can suppress the finding even though the effective
     value is off.

8. Nginx report noise
   - Problem: expanded/effective configs can repeat the same low-severity
     missing-policy advice across multiple server blocks when the root cause
     is one inherited/effective setting.
   - Fix direction: preserve exact source locations, but group or suppress
     duplicate advice where the effective cause is the same.

## Lighttpd Conditional Scopes

Root problem: some Lighttpd rules still treat "directive exists anywhere in the
AST" or "directive exists in any possible conditional branch" as if it applies
to every analyzed host context.

Confirmed issues:

1. `lighttpd.access_log_missing`
   - File: `src/webconf_audit/local/lighttpd/rules/access_log_missing.py`
   - Problem: `accesslog.filename` inside one `$HTTP["host"]` block suppresses
     the missing access-log finding globally, including for other `--host`
     values.

2. `lighttpd.error_log_missing`
   - File: `src/webconf_audit/local/lighttpd/rules/error_log_missing.py`
   - Problem: `server.errorlog` inside one conditional host block suppresses
     the missing error-log finding globally.

3. `lighttpd.missing_strict_transport_security` and
   `lighttpd.missing_x_content_type_options`
   - Files:
     `src/webconf_audit/local/lighttpd/rules/missing_strict_transport_security.py`,
     `src/webconf_audit/local/lighttpd/rules/missing_x_content_type_options.py`
   - Problem: in default no-host analysis, headers present only in one
     possible conditional branch can suppress missing-header findings for the
     whole config.

Fix direction:

- Move missing logging rules to the effective/merged directive model.
- For no-host analysis, distinguish "covered in all relevant branches" from
  "present in one possible branch".
- Keep targeted `--host` behavior strict and context-specific.

## IIS Cross-File Inheritance

Root problem: single-file IIS location inheritance applies collection semantics,
but cross-file effective-config merging can replace inherited children instead
of merging them.

Confirmed issue:

1. Cross-file child collection merge
   - File: `src/webconf_audit/local/iis/effective.py`
   - Problem: when merging `machine.config`, `applicationHost.config`, and
     `web.config`, attributes are layered but child elements can be replaced
     by `override.children`.
   - Example impact: a `web.config` that adds one `customHeaders` entry can
     discard inherited HSTS from `machine.config`, causing false
     `iis.missing_hsts_header`.

Fix direction:

- Reuse IIS `clear` / `remove` / `add` child collection semantics in
  cross-file merges.
- Add regression tests for inherited custom headers, modules, handlers, and
  request-filtering collections.

## Apache Options Regression Coverage

Root problem: Apache has stronger effective-config helpers than the other local
analyzers, but parser-tolerant mixed `Options` modifier forms still need
explicit regression coverage across rule and normalizer paths.

Confirmed follow-up:

1. `Options` modifier ordering
   - File: `src/webconf_audit/local/normalizers/apache_normalizer.py`
   - Cases to pin:
     - `Options Indexes -Indexes`
     - `Options -Indexes Indexes`
   - Expected behavior: apply modifiers left-to-right consistently wherever
     the project chooses to support mixed forms.

Fix direction:

- Add regression tests for rule output and normalized output.
- Keep rule semantics and normalizer semantics aligned so local and universal
  findings do not contradict each other.
