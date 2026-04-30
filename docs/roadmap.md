# Roadmap

This roadmap replaces the old cleanup-oriented planning. The project is moving
from cleanup work to productization: first make the tool reliable in its own
development workflow, then make it easy to run in other projects' CI, then add
clear change-oriented reporting, and only after that expand rule coverage
against security standards.

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

| Server | Notes |
|--------|-------|
| Nginx | Common `server { return 301 ...; }` and rewrite-only redirect hosts. |
| Apache | Common `Redirect`, `RedirectMatch`, and rewrite-only virtual hosts. |
| Lighttpd | Redirect-only conditional scopes can be modeled conservatively. |
| IIS | Applies to `httpRedirect` and rewrite-only sites, while respecting XML inheritance. |

### Inheritance-aware missing checks

Rules that report missing directives should consult the effective parent
configuration before emitting a finding. A server block, virtual host, or site
should not be reported as missing a setting when an inherited value already
applies.

Applicability:

| Server | Notes |
|--------|-------|
| Nginx | Add effective `main -> http -> server -> location` handling for inherited directives. |
| Apache | Extend existing effective helpers so more rules consume inherited `VirtualHost`, `Directory`, and `Location` state. |
| Lighttpd | Combine global directives with conditional scopes where the directive semantics allow inheritance. |
| IIS | Prefer effective merged XML sections for rules that currently inspect only the local document. |

### TLS hardening expansion

Add missing-policy checks where the server exposes the setting locally, and use
external TLS probing where local configuration cannot reliably show the value.

Planned checks:

- Missing TLS protocol policy, for example Nginx `ssl_protocols` or Apache
  `SSLProtocol`.
- TLS session settings, for example Nginx `ssl_session_cache` /
  `ssl_session_timeout` or Apache `SSLSessionCache` /
  `SSLSessionCacheTimeout`.
- OCSP stapling not enabled at all, complementing existing checks for
  incomplete stapling configuration.
- Default TLS virtual host behavior, such as Nginx `listen 443 default_server
  ssl` or the first/default Apache TLS virtual host serving unexpected host
  names without a deliberate catch-all.

Server notes:

| Server | Notes |
|--------|-------|
| Nginx | High-value local coverage for protocol policy, sessions, OCSP stapling, and default TLS hosts. |
| Apache | High-value local coverage for protocol policy, sessions, OCSP stapling, and default TLS virtual hosts. |
| Lighttpd | Coverage depends on the TLS backend and modeled OpenSSL directives. |
| IIS | TLS protocol and cipher policy often lives outside XML; local rules should mark it unknown, while external probing should provide the reliable signal. |

### Severity calibration and report grouping

Tune severity by context instead of treating every missing hardening directive
the same way. Missing HSTS on an active TLS endpoint, missing TLS policy, and
missing request limits on a public file listing can deserve stronger treatment
than generic low-severity advice.

Reports should also group repeated low-severity findings that share the same
rule, recommendation, and effective cause, while preserving exact source
locations in text and JSON output.

## Current Priority

Stage 2 step 4 is now active. `docs/standards-roadmap.md` defines the
standards source baseline, gap labels, work order, and initial backlog for
ASVS 5.0.0, CIS NGINX Benchmark v3.0.0, CIS Apache HTTP Server 2.4 Benchmark
v2.3.0, IIS / Windows Server hardening sources, and future standards-aware
reporting.

Current step: standards metadata in the rule registry / report formats. This
adds machine-readable standards references without changing detector behavior.
After review, start the first new rule PR from the prioritized backlog.
