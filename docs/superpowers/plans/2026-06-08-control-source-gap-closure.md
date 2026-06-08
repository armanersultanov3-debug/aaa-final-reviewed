# Control Source Gap Closure Plan - 2026-06-08

## Goal

Move the remaining not-fully-covered control-source items toward honest partial
or full coverage. The immediate focus is uncovered or uncredited items. Items
that are already partial, such as OWASP Top 10:2025, OWASP ASVS v5.0.0, and
ISO/IEC 27002:2022 partial rows, stay for a later partial-to-full pass.

## Current snapshot

Coverage percent is calculated as:

`full coverage % = fully covered applicable items / applicable items * 100`

Partial items are tracked separately and are not counted in the numerator.

| Control source | Applicable | Full | Partial | Not full | Immediate status |
| --- | ---: | ---: | ---: | ---: | --- |
| CIS NGINX Benchmark v3.0.0 | 15 | 7 | 0 | 8 | Highest volume of not-full source items. |
| CIS Apache HTTP Server 2.4 Benchmark v2.3.0 | 19 | 17 | 0 | 2 | Small number of remaining not-full items, mostly deployment-policy dependent. |
| CIS Microsoft IIS 10 Benchmark v1.2.1 | 10 | 8 | 1 | 2 | One partial item plus one unresolved scope decision around FTP. |
| OWASP Top 10:2025 | 8 | 2 | 6 | 6 | No fully uncovered row in the diploma snapshot; defer partial-to-full work. |
| OWASP ASVS v5.0.0 | 22 | 15 | 7 | 7 | No fully uncovered row in the diploma snapshot; defer partial-to-full work. |
| NIST SP 800-52 Rev. 2 | 10 | 10 | 0 | 0 | No gap. |
| PCI DSS v4.0.1 | 11 | 11 | 0 | 0 | No gap. |
| ISO/IEC 27002:2022 | 10 | 8 | 2 | 2 | Partial-to-full work only; defer. |

## Rules for closing a gap honestly

- A source item can become full only when the project can verify the required
  condition from its actual inputs: local config, normalized effective config,
  optional registry export, or safe external probe.
- A source item can become partial when the project verifies a real narrower
  signal but cannot prove the complete benchmark requirement.
- A source item must stay out of scope when it requires package-manager state,
  file ownership, OS permissions, business-specific routing, application code,
  SIEM state, or operational policy that the tool does not receive.
- New policy-dependent checks must be explicit opt-in checks, not noisy default
  findings.

## PR 1 - Coverage tracker and recount guardrail

Purpose: prevent the coverage table from drifting from rule metadata.

- [ ] Add a compact source-coverage tracker section or file that lists each
  counted item behind the diploma snapshot.
- [ ] For every not-full item, record one of: `direct-rule candidate`,
  `policy-profile candidate`, `partial-only candidate`, `scope decision`, or
  `defer`.
- [ ] Keep the existing percent formula unchanged: full items only count in the
  numerator.
- [ ] Add a short maintenance note explaining that PR #7 strengthened ASVS
  v5.0.0-13.4.5 OpenAPI/Swagger evidence without changing the full numerator.
- [ ] Verification: run the documentation coverage test and `git diff --check`.

Likely files:

- `docs/benchmarks-covering.md`
- `docs/rule-coverage.md`
- `docs/standards-roadmap.md`

Acceptance criteria:

- The table can be recalculated manually from documented item rows.
- No new rule behavior is introduced.
- The tracker clearly distinguishes not-full, partial, and out-of-scope.

## PR 2 - CIS NGINX not-full triage

Purpose: split the eight not-full Nginx items into implementable and
non-implementable groups before adding default rules.

### Nginx CIS §2.5.4 reverse-proxy disclosure

- [ ] Re-read the exact CIS text and decide whether it requires response-header
  suppression, upstream header hygiene, status exposure, or all of them.
- [ ] Compare the requirement with current signals:
  `external.nginx_status_exposed`, generic header rules, and Nginx proxy rules.
- [ ] If the signal is strict enough, add or refine Nginx local proxy-header
  semantics instead of claiming coverage from generic header checks.
- [ ] If only runtime evidence is possible, mark it partial and keep the full
  row open.

Likely code areas:

- `src/webconf_audit/local/nginx/`
- `src/webconf_audit/external/`
- `tests/test_nginx_*.py`
- `tests/test_external_*.py`

Acceptance criteria:

- Full coverage only if the effective Nginx proxy/header model proves the CIS
  requirement.
- Partial coverage only if the limitation is written into `docs/rule-coverage.md`.

### Nginx CIS §3.1 access_log format

- [ ] Keep existing baseline checks for `access_log`, named `log_format`, and
  required fields.
- [ ] Do not treat the built-in default access log format as universally wrong
  without an operator policy.
- [ ] Add an optional policy-profile design if strict SIEM/JSON/default-format
  enforcement is needed later.

Acceptance criteria:

- Default output remains low-noise.
- Any stricter claim is opt-in and documented as policy-based.

### Nginx CIS §4.1.12 HTTP/3 / Alt-Svc

- [ ] Keep the current default decision: not pursued as a noisy default check.
- [ ] Add only an opt-in review rule if user configs with QUIC listeners show
  real false negatives.
- [ ] Candidate shape: detect `listen ... quic` or `listen ... http3` without a
  matching `Alt-Svc` advertisement, and report it as policy review, not as a
  default security failure.

Acceptance criteria:

- No default rule claims HTTP/3 as mandatory.
- If implemented later, it is partial/policy-review unless CIS changes the
  requirement priority.

### Nginx CIS §5.1.1 sensitive-path catalogue

- [ ] Keep the built-in sensitive-path baseline.
- [ ] Design an optional catalog input, for example a YAML/JSON list of
  deployment-specific sensitive paths.
- [ ] Extend local or external checks to consume that catalog safely.
- [ ] Treat full coverage as "full for the supplied catalog", not universal
  knowledge of every possible business-sensitive path.

Acceptance criteria:

- Built-in catalog remains stable.
- User-supplied paths are validated and cannot trigger unsafe probes.

### Nginx CIS §5.2.4-§5.2.5 rate-limit value reasonableness

- [ ] Keep current presence/structure checks and existing review rules.
- [ ] Avoid default numeric thresholds because correct limits depend on traffic
  profile.
- [ ] Later policy-profile candidate: allow an operator-defined min/max policy
  for `limit_req_zone` and `limit_conn_zone`.

Acceptance criteria:

- No hard-coded workload-specific thresholds in default mode.
- Any stricter result clearly states the policy source.

### Nginx CIS §5.3.2-§5.3.3 CSP semantics

- [ ] Reuse existing CSP structural checks where they prove generic unsafe
  directives.
- [ ] Keep full application-specific CSP correctness out of default local
  analysis.
- [ ] Later partial/full path: parse CSP source lists into a normalized model
  and cover only generic directives that are independent from application
  routing.

Acceptance criteria:

- The project does not claim full CSP application authorization semantics from
  static web-server config alone.

## PR 3 - CIS Apache remaining not-full items

Purpose: close or reclassify the two Apache not-full areas without pretending
the config file proves OS/package state.

### Apache CIS §2.1-§2.9 module minimization

- [ ] Keep current `LoadModule` inventory and ModSecurity/CRS rules.
- [ ] Add no default "allowed module list" because legitimate modules vary by
  deployment.
- [ ] Design an optional Apache module policy file:
  allowed modules, required modules, forbidden modules, and justification tags.
- [ ] If implemented, report findings only when the policy file is supplied.

Likely code areas:

- `src/webconf_audit/local/apache/`
- `tests/test_apache_*.py`

Acceptance criteria:

- Full coverage is possible only relative to an explicit module policy.
- Without a policy, the benchmark row remains documented as requiring
  deployment/package context.

### Apache deployment tuning

- [ ] Keep existing direct checks for logs, request limits, headers, methods,
  ModSecurity, and CRS.
- [ ] Separate absolute unsafe values from organization-specific tuning values.
- [ ] Later policy-profile candidate: threshold configuration for
  `LimitRequestBody`, `LogFormat`, and CSP source-list strictness.

Acceptance criteria:

- Existing safe defaults are preserved.
- Policy-based checks do not run unless the user explicitly supplies policy.

## PR 4 - CIS IIS unresolved scope decision

Purpose: decide whether IIS FTP belongs in the product scope. This is the only
large item that could change the denominator rather than simply add a rule.

### Option A - Keep FTP out of scope

- [ ] Document that the analyzer targets HTTP web-server configuration, not IIS
  FTP service configuration.
- [ ] Remove FTP-only items from the applicable denominator in the project
  tracker if they were counted as applicable.
- [ ] Keep the diploma table as historical, but add a current-project note with
  the corrected denominator.

Acceptance criteria:

- The scope statement is consistent across `docs/rule-coverage.md`,
  `docs/standards-roadmap.md`, and `docs/benchmarks-covering.md`.

### Option B - Add minimal IIS FTP config support

- [ ] Parse relevant `<system.ftpServer>` sections from IIS config inputs.
- [ ] Add minimal rules for FTP SSL policy and FTP logon-attempt restrictions.
- [ ] Keep it separated from HTTP analyzer output so the user understands that
  this is an IIS FTP extension.
- [ ] Add fixture coverage for both unsafe and safe FTP configurations.

Likely code areas:

- `src/webconf_audit/local/iis/`
- `tests/test_iis_*.py`
- `demo/local_admin/iis/`

Acceptance criteria:

- The feature must not weaken existing IIS HTTP effective-configuration logic.
- If FTP is added, the table can count the relevant IIS FTP item as at least
  partial; full requires both modeled sections and safe/unsafe fixtures.

### IIS shared application-pool exceptions

- [ ] Keep `iis.sites_share_application_pool` as a real partial signal.
- [ ] Consider an optional allowlist for intentional shared-hosting scenarios.
- [ ] Full coverage should require either no cross-site sharing or an explicit
  allowlist entry.

Acceptance criteria:

- The rule remains useful by default and does not flag documented exceptions as
  unmanageable noise when policy is supplied.

## Deferred partial-to-full work

These rows are already partial in the diploma snapshot and should be handled
after the uncovered/uncredited work above.

### OWASP Top 10:2025

- [ ] Keep it as category-level secondary metadata.
- [ ] Do not claim full coverage for broad categories that include application
  code, identity flows, software supply chain, insecure design, or logging
  process controls.
- [ ] Improve explanatory mapping only after source-level rules improve.

### OWASP ASVS v5.0.0

- [ ] Revisit the seven partial ASVS rows after the next Nginx/Apache/IIS pass.
- [ ] Candidate improvements: CSP parser quality, safer documentation endpoint
  classification, secret exposure allowlists, TLS preference evidence.
- [ ] Keep CSRF, application crypto lifecycle, and application logging outside
  default scope unless the tool receives application/runtime evidence.

### ISO/IEC 27002:2022

- [ ] Revisit the two partial rows after ASVS and CIS improvements.
- [ ] Keep management, SDLC, supplier, and process controls out of scanner
  claims.
- [ ] Prefer topic-grouped mapping, not a misleading per-control claim for every
  broad ISO control.

## Recommended PR sequence

1. Coverage tracker and count guardrail.
2. Nginx CIS triage documentation plus any no-code reclassification.
3. Optional Nginx sensitive-path catalog design and tests.
4. Apache module-policy design and tests.
5. IIS FTP scope decision, either denominator correction or minimal FTP parser.
6. IIS shared application-pool allowlist policy.
7. Recount coverage table and update roadmap after each accepted PR.

## Verification checklist for every implementation PR

- [ ] Add unsafe and safe fixtures.
- [ ] Add tests for false-positive boundaries.
- [ ] Update rule metadata and source mapping only when the rule really proves
  the source item.
- [ ] Update `docs/rule-coverage.md`.
- [ ] Update `docs/standards-roadmap.md` when a `STD-GAP-*` status changes.
- [ ] Update `docs/benchmarks-covering.md` only after the row count changes.
- [ ] Run focused tests for the touched analyzer.
- [ ] Run documentation coverage tests.
- [ ] Run `git diff --check`.

## Current next best action

Start with the coverage tracker/recount guardrail, then handle the IIS FTP
scope decision. That prevents us from spending code effort on a row that may
belong outside the HTTP configuration scope. After that, work through Nginx,
because it has the largest not-full count and the most visible gap percentage.
