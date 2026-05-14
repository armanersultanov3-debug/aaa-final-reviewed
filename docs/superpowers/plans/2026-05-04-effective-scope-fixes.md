# Effective Scope Semantics Fixes Implementation Plan

> **Status: completed.** All tasks below were implemented and merged before
> 2026-05-14; `needfix.md` reports the entire backlog as closed. The plan is
> kept as a historical record of the migration to effective/inherited/
> conditional-scope precision. New related work goes through
> `docs/superpowers/plans/2026-05-14-open-items-followup.md`.

**Goal:** Fix the confirmed effective/inherited/conditional-scope precision bugs collected in `needfix.md`.

**Architecture:** Reuse existing effective-config helpers instead of broad parser refactors. Nginx rules should consume `iter_server_blocks_with_http_directives()` / `effective_child_directives()` for inherited `http` values. Lighttpd rules should use effective or merged directive views instead of raw AST existence checks. IIS cross-file merges should reuse the same child collection semantics already used for single-file location inheritance.

**Tech Stack:** Python 3, pytest, existing `webconf_audit.local.*` analyzers and rule registry.

---

## Task 1: Nginx Inherited Server Policy Rules

**Files:**
- Modify: `src/webconf_audit/local/nginx/rules/missing_access_log.py`
- Modify: `src/webconf_audit/local/nginx/rules/missing_error_log.py`
- Modify: `src/webconf_audit/local/nginx/rules/missing_limit_req.py`
- Modify: `src/webconf_audit/local/nginx/rules/missing_limit_conn.py`
- Modify: `src/webconf_audit/local/nginx/rules/missing_ssl_ciphers.py`
- Modify: `src/webconf_audit/local/nginx/rules/header_utils.py`
- Test: `tests/test_nginx_logging_policy.py`
- Test: `tests/test_nginx_limits_timeouts.py`
- Test: `tests/test_nginx_tls_headers.py`

- [x] Step 1: Change existing regression expectations so inherited `http` access/error logs and `limit_req`/`limit_conn` suppress missing findings.
- [x] Step 2: Add inherited header and inherited `ssl_ciphers` tests.
- [x] Step 3: Run targeted Nginx tests and confirm the new/changed tests fail before production changes.
- [x] Step 4: Update rules to resolve inherited `http` directives with last effective server override where applicable.
- [x] Step 5: Re-run targeted Nginx tests and confirm they pass.

## Task 2: Lighttpd Conditional Missing Rules

**Files:**
- Modify: `src/webconf_audit/local/lighttpd/rules/access_log_missing.py`
- Modify: `src/webconf_audit/local/lighttpd/rules/error_log_missing.py`
- Modify: `src/webconf_audit/local/lighttpd/rules/missing_strict_transport_security.py`
- Modify: `src/webconf_audit/local/lighttpd/rules/missing_x_content_type_options.py`
- Test: `tests/test_lighttpd_rule_controls.py`
- Test: `tests/test_lighttpd_conditions.py`

- [x] Step 1: Add tests where host-conditional access/error log settings do not suppress findings for other hosts.
- [x] Step 2: Add tests where no-host analysis still reports missing security headers when the header only exists in one host branch.
- [x] Step 3: Run targeted Lighttpd tests and confirm failures.
- [x] Step 4: Mark logging rules as effective rules and use `merged_directives` for concrete host behavior.
- [x] Step 5: Require global header presence for no-host missing-header silence; keep host-targeted behavior using `merged_directives`.
- [x] Step 6: Re-run targeted Lighttpd tests.

## Task 3: IIS Cross-File Collection Merge

**Files:**
- Modify: `src/webconf_audit/local/iis/effective.py`
- Test: `tests/test_iis_discovery.py`

- [x] Step 1: Add regression tests proving cross-file custom headers are merged, removed, and cleared with IIS collection semantics.
- [x] Step 2: Run the targeted IIS tests and confirm failures.
- [x] Step 3: Replace cross-file child replacement with `_merge_children(base.children, override.children)`.
- [x] Step 4: Re-run targeted IIS tests.

## Task 4: Apache Options Regression Coverage

**Files:**
- Test: `tests/test_normalizer_apache.py`
- Test: `tests/test_apache_effective_vhosts.py`

- [x] Step 1: Add tests for `Options Indexes -Indexes` and `Options -Indexes Indexes` in normalizer and rule output.
- [x] Step 2: Run targeted Apache tests. If implementation already passes, keep tests as coverage; otherwise fix `apache_normalizer.py`.

## Task 5: Verification And Cleanup

**Files:**
- Modify: `needfix.md`

- [x] Step 1: Mark fixed items in `needfix.md` with implementation notes.
- [x] Step 2: Run targeted suites for Nginx, Lighttpd, IIS, Apache.
- [x] Step 3: Run `ruff check .`.
- [x] Step 4: Run broader fast pytest suite if targeted checks are green.
