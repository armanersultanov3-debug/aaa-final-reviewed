# Roadmap

This roadmap replaces the old cleanup-oriented planning. The project is moving
from cleanup work to productization: first make the tool reliable in its own
development workflow, then make it easy to run in other projects' CI, then add
clear change-oriented reporting, and only after that expand rule coverage
against security standards.

## Post-practice baseline

The pre-graduation practice milestone is complete. The current repository state
is summarized in [project-status.md](project-status.md): implemented scope,
validation status, known boundaries, and the immediate graduation-project work
items.

The next work should stay deliberately narrow:

1. improve parser and effective-configuration precision for the already
   supported server families;
2. continue standards-driven mapping and rule work;
3. grow the external safe-probe catalog without adding active exploitation
   behavior;
4. reduce false positives and improve report explanations;
5. prepare a repeatable packaging and release workflow.

New server-family support is a separate research track. It should not displace
the current four-server core until the existing analyzers, documentation, and
release workflow are stable.

## Stage 1 - CI And Reporting Foundation

Stage 1 has a fixed order. Do not start standards-driven rule expansion until
all three milestones below are complete.

### 1. Project CI For This Repository

Goal: every pull request to this repository must automatically prove that
`webconf-audit` still works.

Implementation plan:

1. Add `.github/workflows/ci.yml`.
2. Run on `pull_request` and pushes to `master`.
3. Use the supported Python range, starting with Python 3.10 and the current
   development version used locally.
4. Install dependencies from the project metadata.
5. Run fast deterministic checks:
   - `ruff check .`
   - `python -m compileall -q src`
   - `pytest tests --ignore=tests/integration_external --ignore=tests/integration_local --ignore=tests/integration_rule_coverage -q`
   - `webconf-audit list-rules`
6. Add a separate manual or scheduled workflow for Docker-backed integration
   tests, because those depend on a live Docker environment.
7. Document the local equivalent command set in `README.md`.

Acceptance criteria:

- CI runs automatically on every PR.
- A normal code-only PR cannot merge with failing lint, unit tests, import
  compilation, or rule registry loading.
- Docker integration tests are available without making every PR depend on a
  local service stack.
- The workflow runs under the repository owner only and does not require
  secrets.

Status: implemented by `.github/workflows/ci.yml`,
`.github/workflows/docker-integration.yml`, the `dev` dependency group, and the
local command set documented in `README.md`.

### 2. CI Integration Features For Users

Goal: make `webconf-audit` usable as a CI gate in real repositories, not only as
an interactive local scanner.

Implementation plan:

1. Define stable finding fingerprints:
   - `rule_id`
   - `server_type`
   - normalized source path or target
   - normalized line/XML path/details where available
   - scope identifier where available
2. Add severity-based exit behavior:
   - `--fail-on medium|high|critical`
   - exit code `0` when no matching findings exist
   - exit code `2` when policy-blocking findings exist
   - exit code `1` for execution/configuration errors
3. Add a suppression file:
   - default path `.webconf-audit-ignore.yml`
   - each suppression must include `rule_id`, locator/fingerprint data,
     `reason`, and `expires`
   - expired suppressions must stop suppressing and emit an analysis issue
   - suppressions without a reason must be rejected
4. Add CI-oriented documentation:
   - GitHub Actions example
   - GitLab CI example
   - Azure DevOps example if the CLI shape is stable
5. Add a minimal SARIF or Markdown CI report only after fingerprints and
   suppressions are stable.

Acceptance criteria:

- Users can fail CI on unsuppressed findings at a chosen severity.
- Users can document accepted risk with an expiry date.
- Suppressed findings are counted separately from active findings.
- CI examples are copy-paste runnable for at least GitHub Actions.
- The default local interactive behavior remains unchanged unless CI flags are
  used.

Status: implemented by stable fingerprints, severity-based CI exit codes,
`.webconf-audit-ignore.yml` suppressions with reason/expiry, and CI examples.

### 3. Baseline/Diff Reporting

Goal: make reports show what is new and what was fixed compared with a previous
known state.

Implementation plan:

1. Reuse the stable finding fingerprint from milestone 2.
2. Add baseline creation from a JSON report:
   - command or flag to write a baseline file
   - baseline stores finding fingerprints plus enough display metadata to be
     useful in review
3. Add diff mode:
   - current findings compared with a baseline
   - findings grouped as `new`, `unchanged`, `resolved`, and `suppressed`
4. Add CI policy over diff results:
   - `--fail-on-new medium|high|critical`
   - optionally keep `--fail-on` for all current unsuppressed findings
5. Improve text and JSON output:
   - text report gets a short diff summary
   - JSON report gets explicit arrays for `new_findings`, `resolved_findings`,
     `unchanged_findings`, and `suppressed_findings`
6. Add tests for fingerprint stability, renamed paths where possible, expired
   suppressions, and resolved findings.

Acceptance criteria:

- A repository with existing debt can keep CI green while blocking new issues.
- A cleanup PR can clearly show which findings disappeared.
- JSON output is machine-readable enough for downstream dashboards.
- Text output stays readable for humans and does not bury new findings.

Status: implemented by baseline files, `--baseline`, `--write-baseline`,
`--fail-on-new`, and diff-aware text/JSON report output.

## Stage 2 - Standards-Driven Rule Expansion

Stage 2 starts only after Stage 1 is complete.

Goal: expand rules deliberately using CWE, OWASP, CIS, and similar references,
instead of adding one-off checks opportunistically.

Process:

1. Generate a current rule inventory:
   - rule id
   - server type
   - severity
   - tags
   - data source required
   - current tests
2. Create `docs/rule-coverage.md`.
3. Map current rules to standards where the mapping is honest:
   - CWE where a rule has a clear weakness class
   - OWASP where a rule supports an application security control
   - CIS or vendor hardening guidance where a rule is configuration-specific
4. For candidate standards items, classify each gap and record the standards
   backlog in `docs/standards-roadmap.md`:
   - direct rule can be added now
   - rule requires deeper parser/effective-config analysis
   - rule requires deeper external probing
   - rule is out of scope for this tool
5. Implement new work in small PRs:
   - first add parser/probe depth when needed
   - then add the rule
   - then add mapping metadata and tests

Acceptance criteria:

- Every new standards-driven rule has a clear source reference.
- Rules that require deeper analysis are not hacked around with weak string
  matching.
- Rule metadata can eventually power reports grouped by standard.
- The project keeps false positives lower priority than raw rule count.

## Cross-Server Precision Backlog

These items support the Stage 2 goal of adding coverage without increasing
noise. They should be handled before or alongside new rule families when the
same limitation would otherwise create repeated false positives.

### Redirect-only scopes

Detect scopes that only redirect requests and do not serve local content. For
those scopes, skip checks that do not meaningfully apply to redirect responses,
such as content security headers, hidden-file deny rules, backup-file deny
rules, body-size limits, and per-content rate limits.

Applicability:

| Server | Status | Evidence / next proof | Notes |
|--------|--------|-----------------------|-------|
| Nginx | Confirmed / covered | Reproduced from the real `Новая папка` report and covered by `tests/test_nginx_roadmap1_noise.py`. | Common `server { return 301 ...; }` and rewrite-only redirect hosts. |
| Apache | Confirmed / covered | Covered by Apache redirect-only VirtualHost regression tests. | Common `Redirect`, `RedirectMatch`, and rewrite-only virtual hosts. |
| Lighttpd | Covered | `tests/fixtures/webserver-configs/lighttpd/edge-cases/` plus `tests/test_lighttpd_redirect_inheritance_fixtures.py` exercise redirect-only `$SERVER["socket"] == ":80"` conditional blocks and host-conditional `url.redirect`. | Redirect-only conditional scopes can be modeled conservatively. |
| IIS | Confirmed / covered | Covered for global `httpRedirect enabled="true"` with `childOnly` guard. | Applies to `httpRedirect` and rewrite-only sites, while respecting XML inheritance. |

### Inheritance-aware missing checks

Rules that report missing directives should consult the effective parent
configuration before emitting a finding. A server block, virtual host, or site
should not be reported as missing a setting when an inherited value already
applies.

Applicability:

| Server | Status | Evidence / next proof | Notes |
|--------|--------|-----------------------|-------|
| Nginx | Partially covered | Logging, timeout, header, TLS, stapling, HTTP/2, and fragment-only notes have regression coverage; the current parser already resolves includes and effective config for the supported input model, so `nginx -T` dump reconstruction is out of scope until user demand because it reduces source-location quality. | Continue extending effective `main -> http -> server -> location` handling within the current parser model rather than adding an alternative `nginx -T` input mode. |
| Apache | Covered for current model | Apache effective helpers are consumed by the log-presence, log-value, LogFormat resolution, `directory_without_allowoverride`, deny-list, header, TLS, timeout, limit, and method-policy rule families; `tests/test_apache_inheritance_*.py` exercise the inheritance scenarios end-to-end. | Remaining rule migrations are tracked rule-by-rule rather than as a backlog item. |
| Lighttpd | Covered | Request-context inheritance fixtures (`tests/test_lighttpd_redirect_inheritance_fixtures.py`) exercise global directives with conditional scopes for logging and security headers. | Combine global directives with conditional scopes where the directive semantics allow inheritance. |
| IIS | Confirmed / covered | Covered by `tests/test_iis_inheritance_fixtures.py` and the IIS inheritance-edge fixtures for handlers, modules, and requestFiltering. | Effective merged XML sections now have cross-file regression coverage across `machine.config`, `applicationHost.config`, and `web.config`. |

### TLS hardening expansion

Add missing-policy checks where the server exposes the setting locally, and use
external TLS probing where local configuration cannot reliably show the value.

Planned checks:

- Missing TLS protocol policy, for example Nginx `ssl_protocols` or Apache
  `SSLProtocol`.
- TLS session settings, for example Nginx `ssl_session_cache` /
  `ssl_session_timeout` or Apache `SSLSessionCache` /
  `SSLSessionCacheTimeout`. Status: covered for Nginx and Apache local
  analysis with inherited/effective-scope regression tests.
- OCSP stapling completeness across local TLS server-family rules.
- Default TLS virtual host behavior, such as a deliberate Nginx
  `listen 443 ssl default_server` catch-all or the first/default Apache TLS
  virtual host rejecting unexpected host names.

Server notes:

| Server | Status | Evidence / next proof | Notes |
|--------|--------|-----------------------|-------|
| Nginx | Covered for current model | Protocol policy, session cache, session timeout, OCSP stapling completeness, and default TLS catch-all handling all have targeted local regression coverage. | No mandatory Nginx-local TLS baseline tail remains in the current model; deeper runtime TLS posture is covered by external probes, while deployment-specific exceptions stay operator context. |
| Apache | Covered for current model | Apache TLS tests cover protocol policy, cipher policy, stapling cache, session cache, session cache timeout, default TLS VirtualHost unknown-host rejection, and the Apache CIS precision tail around request-policy and upstream proxy trust. | No mandatory Apache-local CIS baseline tail remains in the current model; deployment-specific exceptions stay documentation/operator context, while deeper runtime TLS posture is covered by external probes. |
| Lighttpd | Out-of-scope for now | Lighttpd supports multiple TLS backends (`mod_openssl`, `mod_gnutls`, `mod_wolfssl`, `mod_mbedtls`), so a generic cross-backend rule would be inaccurate. | Revisit per-backend rule extensions in a future cycle if backend-specific semantics become worth modeling. |
| IIS | External-first | Local XML often cannot prove Schannel policy; external probing is the more reliable signal. | TLS protocol and cipher policy often lives outside XML; local rules should mark it unknown, while runtime certificate, protocol, cipher-preference, and OCSP evidence now come from external probes. |

### Severity calibration and report grouping

Tune severity by context instead of treating every missing hardening directive
the same way. Missing HSTS on an active TLS endpoint, missing TLS policy, and
missing request limits on a public file listing can deserve stronger treatment
than generic low-severity advice.

Reports should also group repeated low-severity findings that share the same
rule, recommendation, and effective cause, while preserving exact source
locations in text and JSON output.

Status: first implementation added opt-in text grouping via
`--group-repeated` and JSON `finding_groups` that keep the original flat
`findings` array intact. Severity calibration now uses the profile-based
methodology in `docs/severity-methodology.md`; every built-in rule has an
impact/exposure/exploitability/confidence/context profile, and the registry
derives default severity from that profile.

Current execution order after the report-grouping merge:

1. Validate `--group-repeated` against the real noisy Nginx evidence captured
   in `tests/test_nginx_roadmap1_noise.py`, comparing the current output with
   the saved prototype report.
2. Continue CIS/standards coverage expansion and curated safe-probe growth on
   top of the now-implemented Apache precision and TLS runtime evidence work.

### External safe probe catalog

The existing `analyze-external` mode already performs safe runtime probing,
server fingerprinting, TLS checks, redirect analysis, and fixed sensitive-path
checks. To grow external coverage without turning the tool into an active
exploitation scanner, add a declarative catalog for safe probe rules before
adding more hardcoded path checks.

Initial scope:

- fixed `GET`, `HEAD`, and `OPTIONS` requests only;
- simple status, header, body, and content-type matchers;
- per-rule metadata for severity, tags, standards references, and server
  conditions;
- curated Nuclei-template ideas only where they fit the safe subset.

Out of scope for this mode: fuzzing, payload injection, brute force,
state-changing HTTP methods, OOB callbacks, authentication bypass attempts,
and exploit chains.

Status: initial fixed-path exposure checks are catalog-backed by
`src/webconf_audit/external/safe_probe_catalog.py`. The first cataloged set
keeps the existing `GET` sensitive-path probes and rule IDs intact; follow-up
work can add curated safe probes from external sources without adding another
hardcoded finder per path. The current catalog also includes batch-4 path
variants for existing environment-file, database-dump, dependency-manifest,
and backup-archive rules; this increases observable fixed-path coverage
without increasing rule count or changing the external probing model.

## Backlog Status (local snapshot date: 2026-05-15)

- Rule count: 466 total (including 9 opt-in `policy-review` rules excluded
  from default analyzer runs; safe-probe batch-3 added 30 new external
  rules and batch-4 added 11 path variants per STD-GAP-015), with the
  repeated counters and registry expected to stay aligned.
- Closed STD-GAP items: `STD-GAP-001`-`STD-GAP-014`, `STD-GAP-016`,
  `STD-GAP-020`, `STD-GAP-021`, `STD-GAP-024`, `STD-GAP-026`-`STD-GAP-032`,
  `STD-GAP-035`, `STD-GAP-036`, `STD-GAP-037`, and `STD-GAP-038`.
- Closed as not pursued (see rationale in `docs/benchmarks-covering.md §9`):
  `STD-GAP-017`, `STD-GAP-018`, `STD-GAP-019`, `STD-GAP-022`, `STD-GAP-023`,
  `STD-GAP-025`, `STD-GAP-033`, and `STD-GAP-034`.
- Active backlog:
  - `STD-GAP-015` — ongoing safe-probe catalog growth (PR-3 of plan
    2026-05-14 landed batch-2 with ~30 new external rules; later catalog
    growth added batch-3 dashboard/control-plane rules and batch-4 file/path
    variants; further growth remains open as new safe candidate paths surface).

## Current Priority

The immediate priority is no longer broad local/static rule addition. The
high-value precision work that fit the current analyzer model is mostly
implemented: report-noise grouping, redirect-only scope handling, severity
calibration, request/body/header limit quality, logging quality,
sensitive-path deny policy, header policy quality, local TLS complements, and
IIS XML policy completeness are all present.

Current work should continue in five lanes:

1. **Precision lane** - close false-positive cases that have concrete
   fixtures, especially where inherited/effective configuration or
   redirect-only behavior changes rule applicability.
2. **Standards lane** - keep `docs/standards-roadmap.md` and
   `docs/rule-coverage.md` aligned with the rule registry, and add new
   mappings only when the scanner signal is honest.
3. **External lane** - add curated non-mutating safe probes on top of
   `src/webconf_audit/external/safe_probe_catalog.py` and the existing TLS
   evidence layer.
4. **Reporting lane** - improve explanations, grouping, and source locations
   without changing the stable JSON contract unnecessarily.
5. **Release lane** - keep packaging, installation, versioning, changelog
   entries, release tags, and installed-package checks repeatable before
   deciding whether public package publishing is useful.

Two Nginx-local items remain explicitly **closed as not pursued
(2026-05-15)**: raw backend response reading (see
`docs/testing-real-world-configs.md` for trigger conditions) and HTTP/3
detection (see `docs/rule-coverage.md` §4.1.12).
