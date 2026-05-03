# Needfix

Сводка на 2026-05-03 по ревью репозитория `aaa-final-reviewed` и PR #1
`aaa-final-reviewed-security-audit`.

Источники:

- CodeRabbit: PR #1 `[codex] CodeRabbit tail review`
  (`armanersultanov8-cmd/aaa-final-reviewed-security-audit#1`).
- CodeRabbit: предыдущие actionable findings по основному diff.
- Superpowers review: полный локальный review репозитория `aaa-final-reviewed`.
- Codex Security: `report.md` Final Report for full repository snapshot at
  `HEAD 6b4b571`, plus full-repo diff branch `security-audit-full-diff` against
  an empty baseline.

## Приоритет исправления

1. P2 runtime/security semantics: IIS `defusedxml` exception normalization.
2. P2 nginx effective directive semantics: last-wins and inherited `http` scope for
   TLS/stapling/http2 rules.
3. P2 Apache `Options` modifier ordering.
4. P3 nginx log format default handling.
5. Test-only PR #1 CodeRabbit findings: registry isolation and offline/strict tests.
6. Low-risk lint/refactor items from PR #1.

## Codex Security

Result from `report.md`: no high-impact exploitable vulnerability found. The
meaningful issues are rule-semantics correctness bugs that can cause false
negatives/positives in this security audit tool.

Reportable findings:

1. `src/webconf_audit/local/nginx/rules/ssl_stapling_missing_resolver.py`
   - Finding: nginx `ssl_stapling_missing_resolver` should use effective
     last-directive semantics.
   - Risk: repeated directives can be interpreted differently from nginx runtime
     behavior, causing false positives or false negatives.

2. `src/webconf_audit/local/nginx/rules/missing_ssl_prefer_server_ciphers.py`
   - Finding: nginx `missing_ssl_prefer_server_ciphers` should use effective
     last-directive semantics.
   - Risk: an earlier `on` or missing inherited value can mask the real effective
     TLS hardening state.

3. `src/webconf_audit/local/normalizers/apache_normalizer.py`
   - Finding: Apache normalizer `Options` handling should apply ordered modifiers
     left-to-right.
   - Risk: `Indexes`, `+Indexes`, and `-Indexes` can be reported with the wrong
     effective state.

4. `src/webconf_audit/local/iis/parser/parser.py`
   - Finding: IIS parser should convert `defusedxml` unsafe-feature exceptions into
     structured `IISParseError` diagnostics.
   - Risk: malicious or unsafe IIS XML can crash analysis instead of producing a
     structured parse error.

CodeRabbit status captured in `report.md`:

- Full diff exceeded CodeRabbit 300-file limit.
- Chunked review succeeded for the 250-file chunk, then 36-file subchunks `2-0`,
  `2-1`, and `2-2`.
- Remaining test-only tail chunks timed out repeatedly; PR #1 tail review later
  produced the CodeRabbit findings listed below.

Verification captured in `report.md`:

- `uv run ruff check .`: passed.
- `uv run pytest -q`: `2095 skipped, 0 failures`.

## CodeRabbit

### PR #1 tail review

1. `tests/test_report.py:539-549` [Major]
   - Finding: test clears the shared rule registry singleton and does not restore it.
   - Risk: suite can become order-dependent because later tests observe the mutated
     global registry.
   - Fix: snapshot and restore registry state in `finally`/teardown, or use an
     isolated fixture/monkeypatch so `JsonFormatter`/`ReportData` operate on a
     temporary registry.

2. `tests/test_lighttpd_conditions.py:1045-1048`, `1086-1089` [Minor]
   - Finding: `assert len(tag_findings_a) >= 1` and analogous directory assertions
     allow duplicate emissions of the same `rule_id`.
   - Risk: regression that emits duplicated findings still passes.
   - Fix: after filtering to the expected rule, assert exact counts such as `== 1`
     while keeping zero assertions for the negative path.

3. `tests/test_tls_probe.py:381-389` [Minor]
   - Finding: negative test monkeypatches `probe_tls_versions` but delegates to the
     real `probe_tls_versions()`.
   - Risk: if the HTTP-only path regresses, the test may perform real network I/O.
   - Fix: make the tracking stub fully deterministic/offline, for example by
     returning a fixed `TLSVersionProbeResult` list or raising a sentinel if called.

4. `tests/test_nginx_limits_timeouts.py:1091-1103` [Minor, outside diff]
   - Finding: test for `missing_limit_req` only asserts the result type.
   - Risk: a regression where `nginx.missing_limit_req` is not emitted would pass.
   - Fix: assert `result.issues == []` and assert at least one finding has
     `rule_id == "nginx.missing_limit_req"`.

5. `tests/test_local_nginx.py:217-245`, `247-275`, `277-307`, `309-340`,
   `399-429` [Trivial]
   - Finding: repeated background-thread-with-timeout pattern across five tests.
   - Fix: extract a helper such as
     `_run_with_timeout(fn: Callable[[], AnalysisResult], timeout=1.0,
     hang_message="Analysis hung") -> AnalysisResult`.

6. `tests/test_rule_registry_integrity.py:51-53` [Trivial]
   - Finding: Ruff PT001 prefers `@pytest.fixture` over `@pytest.fixture()`.
   - Fix: remove fixture decorator parentheses.

7. `tests/test_rule_registry_integrity.py:137-146` [Trivial]
   - Finding: manual list construction can be replaced with list comprehensions.
   - Risk: lint/performance style only.
   - Fix: build `all_ids` with comprehensions for registered entries and external
     metadata, then keep the duplicate assertion.

### Earlier CodeRabbit core review

1. `src/webconf_audit/local/nginx/rules/ssl_stapling_missing_resolver.py:43` [P2]
   - Finding: rule uses `any()` for `ssl_stapling`.
   - Risk: repeated directives are not resolved with nginx last-directive-wins
     semantics, so an earlier `ssl_stapling on` followed by a later effective `off`
     can be misreported.
   - Fix: compute the effective stapling value from inherited scopes and the last
     applicable directive.

2. `src/webconf_audit/local/nginx/rules/missing_ssl_prefer_server_ciphers.py:49`
   [P2]
   - Finding: any earlier `ssl_prefer_server_ciphers on` is treated as sufficient.
   - Risk: a later `off` can hide a TLS hardening regression.
   - Fix: compute the effective value using inherited `http` scope and the last
     server override.

3. `src/webconf_audit/local/normalizers/apache_normalizer.py:514` [P2]
   - Finding: Apache `Options` modifiers are not applied in order.
   - Risk: `Options Indexes -Indexes` and `Options -Indexes Indexes` have different
     effective outcomes, but the helper returns on the first matching token.
   - Fix: process every `Options` token in order and keep the final effective
     `Indexes` state.

4. `src/webconf_audit/local/iis/parser/parser.py:96` [P3]
   - Finding: `defusedxml` unsafe XML exceptions are not normalized.
   - Risk: blocked XML features can raise `DefusedXmlException` and escape instead
     of becoming structured `IISParseError`.
   - Fix: catch `defusedxml.common.DefusedXmlException` and wrap it in
     `IISParseError`.

## Superpowers review

1. `src/webconf_audit/local/iis/parser/parser.py:94-102` [P2]
   - Finding: IIS XXE-block exceptions crash analysis.
   - Reproduction summary: malicious XML with `DOCTYPE` raises `EntitiesForbidden`,
     not `ET.ParseError`; `analyze_iis_config()` crashes instead of returning
     structured `iis_parse_error`.
   - Fix: catch `defusedxml.common.DefusedXmlException` and wrap it in
     `IISParseError`.

2. `src/webconf_audit/local/nginx/rules/missing_ssl_prefer_server_ciphers.py:42-50`
   [P2]
   - Finding: rule checks only direct server directives and uses `any()`.
   - Reproduction summary: inherited
     `http { ssl_prefer_server_ciphers on; }` still reports missing, while
     `ssl_prefer_server_ciphers on; ssl_prefer_server_ciphers off;` reports nothing.
   - Fix: compute the effective value from inherited `http` scope plus the last
     server override.

3. `src/webconf_audit/local/nginx/rules/ssl_stapling_missing_resolver.py:39-45`
   [P2]
   - Finding: stapling and resolver are modeled as direct server children only.
   - Reproduction summary: rule misses `http { ssl_stapling on; }` with no resolver
     and falsely reports when `resolver` is inherited from `http`.
   - Fix: resolve effective `ssl_stapling` and `resolver` across `http`/`server`
     scopes using last-applicable value.

4. `src/webconf_audit/local/nginx/rules/ssl_stapling_without_verify.py:39-46`
   [P2]
   - Finding: inherited `ssl_stapling on` skips verify check.
   - Reproduction summary:
     `http { ssl_stapling on; server { ... } }` with no
     `ssl_stapling_verify on;` produces no
     `nginx.ssl_stapling_without_verify` finding.
   - Fix: reuse the effective http/server stapling resolution pattern from
     `ssl_stapling_disabled.py` and apply the same effective-value logic to verify.

5. `src/webconf_audit/local/nginx/rules/missing_http2_on_tls_listener.py:71-75`
   [P3]
   - Finding: HTTP/2 rule misses inherited and later-off states.
   - Reproduction summary: false positive for
     `http { http2 on; server { listen 443 ssl; ... } }` and false negative for
     `http2 on; http2 off;`.
   - Fix: resolve effective `http2` across `http`/`server` scopes and use the last
     applicable value.

6. `src/webconf_audit/local/nginx/rules/log_format_missing_fields.py:79-84` [P3]
   - Finding: path-only `access_log` default format is ignored.
   - Reproduction summary: nginx treats `access_log /path;` as using the default
     `combined` format, but the helper skips `len(args) < 2`, so a weakened
     `log_format combined ...` is never checked.
   - Fix: treat path-only `access_log` as `combined` unless logging is `off`.

## Deduplicated fix list

1. IIS parser
   - Fix `defusedxml` exception normalization once in
     `src/webconf_audit/local/iis/parser/parser.py`.
   - Add a regression test with unsafe XML/DOCTYPE that returns structured
     `iis_parse_error` instead of crashing.

2. Nginx effective directive handling
   - Introduce or reuse a helper for inherited `http` scope plus server override
     resolution with last-directive-wins semantics.
   - Apply it to:
     - `missing_ssl_prefer_server_ciphers.py`
     - `ssl_stapling_missing_resolver.py`
     - `ssl_stapling_without_verify.py`
     - `missing_http2_on_tls_listener.py`
   - Add tests for inherited `on`, inherited resolver/verify, and later `off`.

3. Apache `Options`
   - Update option normalization to process `Indexes`, `+Indexes`, and `-Indexes`
     in order.
   - Add regression cases for `Options Indexes -Indexes` and
     `Options -Indexes Indexes`.

4. Nginx log format
   - Treat `access_log /path;` as default `combined` format.
   - Add a regression test where weakened `combined` is detected through a
     path-only access log.

5. PR #1 test-only tail
   - Restore registry state in `tests/test_report.py`.
   - Tighten Lighttpd duplicate-count assertions.
   - Make TLS probe negative test fully offline.
   - Strengthen `missing_limit_req` assertion.
   - Optionally extract repeated nginx timeout helper and apply Ruff cleanups.

## Verification notes from Superpowers review

- `uv run ruff check .`: passed.
- `uv run python -m compileall -q src`: passed.
- `uv run webconf-audit list-rules`: passed.
- Main non-integration suite: `2075 passed`.
- Targeted nginx/IIS suite: `233 passed`.
- CodeRabbit CLI supplemental review could not run on the whole tail because the
  change set exceeded the 300-file limit; PR #1 CodeRabbit tail review completed
  successfully and produced the PR #1 findings above.
