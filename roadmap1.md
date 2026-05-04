# Roadmap 1 - Nginx Noise From Real Config Prototype

## Context

This roadmap captures the first two issues found while running the
`aaa-final-reviewed` prototype against the user's own live Nginx configuration.
The evidence is in the local folder `F:\Projects\Новая папка`:

- `app.conf` - the analyzed Nginx site fragment.
- `effective-nginx.conf` - include-expanded Nginx configuration from the live
  container / host.
- `1.txt` - saved `webconf-audit` text report.
- `nginx-test.log` - `nginx -t` output showing the configuration is syntactically
  valid.

Do not treat these files as public scanning targets. If any of this evidence is
turned into fixtures, sanitize the real domain names and certificate paths first.

## Validation Summary

### Problem 1: HTTP redirect block noise

Validated, with one important nuance.

Evidence:

- `app.conf:1` starts an HTTP `server` block listening on port 80.
- `app.conf:8-10` serves only the ACME challenge path from
  `/.well-known/acme-challenge/`.
- `app.conf:12-14` redirects normal traffic with
  `return 301 https://...$request_uri`.
- `1.txt` reports 33 total findings.
- 17 findings are attached to `app.conf:1`.

Findings attached to the HTTP block include:

- `nginx.missing_content_security_policy`
- `nginx.missing_x_frame_options`
- `nginx.missing_x_content_type_options`
- `nginx.missing_referrer_policy`
- `nginx.missing_permissions_policy`
- `nginx.missing_x_xss_protection`
- `nginx.missing_hidden_files_deny`
- `nginx.missing_backup_file_deny`
- `nginx.missing_limit_req`
- `nginx.missing_limit_conn`
- `nginx.missing_client_max_body_size`

These are noisy for the normal port-80 application path because that path only
returns a redirect and does not serve application content. The nuance is that
the block is not strictly "redirect-only": it has an ACME exception. The
implementation should therefore model this as a redirect-only or
redirect-dominant server with safe local exceptions, not as a naive "any return
301 means skip everything" rule.

### Problem 2: Fragment-only analysis and inherited settings

Validated for some directives, and partially validated as "unknown context" for
others.

Evidence:

- `1.txt` targeted only the site fragment: `../2/nginx/conf/app.conf`.
- `effective-nginx.conf:15-33` shows the parent `http {}` context.
- `effective-nginx.conf:23` defines `access_log`.
- `effective-nginx.conf:28` defines `keepalive_timeout`.
- `effective-nginx.conf:6` defines `error_log` in the main context.

Therefore, findings such as missing access log, missing error log, and missing
keepalive timeout can be false positives when the tool is run against only a
`conf.d` fragment instead of the root `nginx.conf`.

For `client_body_timeout`, `client_header_timeout`, and `send_timeout`, the
provided `effective-nginx.conf` does not show explicit directives. These should
not be called proven inherited false positives from this evidence alone. The
correct product behavior is still to mark fragment-only missing-policy findings
as context-sensitive, for example "possibly inherited from the parent Nginx
configuration or left at the Nginx default", unless the analyzer has the full
include-expanded configuration.

## Goal

Reduce false positives and report noise for Nginx local analysis before adding
more Nginx rule coverage.

Priority order:

1. Detect redirect-only / redirect-dominant HTTP scopes and skip checks that do
   not apply to redirect responses.
2. Add fragment-awareness for inherited or defaulted directives when only a
   site fragment is analyzed.
3. Only after those two are stable, continue with severity calibration, TLS
   expansion, and report-level grouping.

## Cross-Server Applicability

The concrete evidence in `F:\Projects\Новая папка` is Nginx-specific, so
Roadmap 1 should still be implemented for Nginx first. However, the underlying
bug class is not Nginx-only.

The same two noise patterns can appear in other supported local analyzers:

1. Redirect-only or redirect-dominant scopes.
   - Apache: HTTP `VirtualHost` blocks that only use `Redirect`,
     `RedirectMatch`, or rewrite rules to send traffic to HTTPS can receive
     irrelevant missing-header, request-limit, or file-deny findings.
   - Lighttpd: conditional host blocks that only set redirect rules can be
     incorrectly treated as content-serving scopes.
   - IIS: sites or locations using `httpRedirect` / rewrite-only behavior can
     receive findings for controls that only matter when local content is
     served.

2. Fragment-only / incomplete-context analysis.
   - Apache: analyzing a single vhost or included file can miss inherited
     global `LogLevel`, `ErrorLog`, `CustomLog`, `LimitRequestBody`, `Header`,
     or directory policy.
   - Lighttpd: analyzing one included config can miss global directives and can
     confuse conditional host scope with global scope.
   - IIS: analyzing one `web.config` without `machine.config` or
     `applicationHost.config` can miss inherited XML section policy.

Roadmap 1 does not implement the cross-server fixes yet. It should create the
Nginx pattern carefully enough that later Apache, Lighttpd, and IIS work can
reuse the same concepts:

- classify whether a scope serves content or only redirects;
- distinguish complete root configuration analysis from partial fragment
  analysis;
- preserve exact findings, but annotate low-confidence missing-policy findings
  when the analyzer does not have the parent context.

## P0: Redirect-Only / Redirect-Dominant Scope Handling

### Design

Add a shared Nginx scope classifier, most likely in a small helper module such
as `src/webconf_audit/local/nginx/rules/_scope_utils.py`.

The classifier should distinguish:

- `serves_content`: normal application content may be served.
- `redirect_only`: all request paths in the scope terminate in `return 301`,
  `return 302`, `return 307`, `return 308`, or an equivalent rewrite redirect.
- `redirect_with_safe_exceptions`: normal traffic redirects, but narrowly scoped
  operational paths such as `/.well-known/acme-challenge/` may serve minimal
  local files.
- `unknown`: the analyzer cannot prove redirect-only behavior.

The classifier must be conservative. If a block has `proxy_pass`, `fastcgi_pass`,
`try_files`, `root`, `alias`, or content-serving locations outside safe
exceptions, treat it as `serves_content` or `unknown`.

### Rules To Skip For Redirect-Only Normal Traffic

For `redirect_only` and carefully validated `redirect_with_safe_exceptions`,
skip these server-scope findings on the redirecting HTTP block:

- Browser content headers:
  - `nginx.missing_content_security_policy`
  - `nginx.missing_x_frame_options`
  - `nginx.missing_x_content_type_options`
  - `nginx.missing_referrer_policy`
  - `nginx.missing_permissions_policy`
  - `nginx.missing_x_xss_protection`
- Content-file exposure guards:
  - `nginx.missing_hidden_files_deny`
  - `nginx.missing_backup_file_deny`
- Request body / abuse limits that do not apply to redirect responses:
  - `nginx.missing_client_max_body_size`
  - `nginx.missing_limit_req`
  - `nginx.missing_limit_conn`

Do not skip:

- Logging checks.
- `server_tokens` / disclosure checks.
- HTTP-to-HTTPS redirect correctness checks.
- TLS checks on TLS server blocks.
- Checks for content-serving exceptions if the exception itself is broad or
  unsafe.

### Regression Tests

Add focused tests using sanitized versions of the real shape:

- HTTP server with ACME challenge plus `location / { return 301 ...; }`.
- HTTPS server with real content and `autoindex on`.
- Assert the listed redirect-noise rules are absent for the HTTP server line.
- Assert important findings on the HTTPS server still appear, for example
  `nginx.autoindex_on` and selected missing security headers.
- Assert a server that has `return 301` in one location but serves content in
  another broad location is not treated as redirect-only.

Avoid exact total-count assertions. Assert specific rule IDs and source
locations.

## P1: Fragment-Aware Inheritance / Unknown Context Notes

### Design

When the target file looks like a site fragment, not a root Nginx config, the
analyzer should avoid presenting inheritable missing directives as definitive.

Fragment signals:

- Top-level file contains `server` blocks but no `http` block.
- Source path resembles `conf.d/*.conf` or `sites-enabled/*`.
- Include metadata is absent, meaning the analyzer did not resolve the parent
  `nginx.conf`.

For missing checks whose directives can be inherited from `main` or `http`, add
structured context metadata to the finding, for example:

```json
{
  "analysis_context": "fragment_only",
  "confidence": "contextual",
  "note": "This directive may be inherited from the parent nginx.conf; analyze the root nginx.conf for a definitive result."
}
```

The text formatter should render a short note under those findings. JSON should
preserve the metadata for downstream consumers.

### Directives In Scope First

Start with the exact noisy family from the real run:

- `access_log`
- `error_log`
- `keepalive_timeout`
- `client_body_timeout`
- `client_header_timeout`
- `send_timeout`

Then extend to other inherited Nginx directives only after the first slice is
covered by tests.

### Full-Config Behavior

If the analyzer receives the root `nginx.conf` or an include-expanded config,
it should use effective values instead of fragment notes:

- `http { access_log ...; }` should satisfy server logging checks.
- main-context `error_log` should satisfy server error-log checks if Nginx
  inheritance semantics make it effective.
- `http { keepalive_timeout ...; }` should satisfy the missing keepalive check.

### Regression Tests

Add two complementary fixture shapes:

1. Fragment-only `app.conf`:
   - Contains only `server {}` blocks.
   - Missing inherited directives should either carry the fragment note or be
     reported in a clearly contextual way.
2. Root `nginx.conf` with `http { include conf.d/app.conf; ... }`:
   - Parent `access_log`, `error_log`, and `keepalive_timeout` should be
     respected.
   - No fragment-only note should appear.

Again, avoid exact total counts. Assert only stable rule IDs, locations, and
metadata notes.

## Implementation Order

1. Add sanitized fixture(s) based on `F:\Projects\Новая папка\app.conf`.
2. Write failing tests for redirect-noise suppression.
3. Implement the Nginx redirect scope classifier.
4. Wire the classifier into only the redirect-noise rules listed in P0.
5. Run targeted Nginx tests.
6. Write failing tests for fragment-only context metadata.
7. Implement fragment detection and finding metadata notes.
8. Teach text/JSON report output to preserve and display the notes.
9. Run targeted tests, lint, then the broader local test set that does not need
   Docker or external network access.

## Acceptance Criteria

- The sanitized reproduction no longer emits browser-header, hidden/backup deny,
  body-size, or rate-limit findings on the HTTP redirect block.
- The HTTPS content-serving block still emits relevant findings.
- Fragment-only analysis clearly marks inherited/default-sensitive missing
  checks as contextual instead of definitive.
- Root or include-expanded analysis uses effective parent directives where they
  exist.
- No external scanning is added.
- No real domains, certificates, keys, or credentials are committed in fixtures.

## Explicitly Out Of Scope For Roadmap 1

- Severity recalibration.
- New TLS hardening rules.
- Report-level grouping of repeated findings.
- Cross-server redirect-only logic for Apache, Lighttpd, or IIS.
- Broad rule-engine refactors.
