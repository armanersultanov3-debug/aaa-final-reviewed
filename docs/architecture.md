# Architecture

## 1. Purpose

`webconf-audit` is a security auditing tool for web server
configurations. It detects misconfigurations, insecure parameters,
and deviations from common hardening guidelines.

The tool has two independent analysis modes:

- **Local** — static analysis of configuration files;
- **External** — black-box probing of a running web endpoint.

Both modes are part of the product and ship in the same package, but
they have different pipelines and different data sources.

## 2. Supported servers

Local analysis covers four web servers:

- Nginx
- Apache HTTP Server
- Lighttpd
- Microsoft IIS

External probing is server-agnostic, with a few server-specific
checks that are activated only after fingerprinting identifies the
underlying server.

## 3. Design principles

1. **Separation of local and external modes.** Two independent
   pipelines with different data sources and different semantics.
   The two modes share only the result/report data model.

2. **Static local analysis.** Local mode does not start the web
   server and does not depend on a running environment.

3. **Minimal normalization.** A unified data model is used only for
   directly comparable entities consumed by universal rules. Every
   server keeps its own representation otherwise.

4. **Traceability.** Every finding and every analysis issue is
   linked to its source:
   - file path and line number for text-based configurations;
   - file path and XML node or section for IIS;
   - observed endpoint, URL, header, or TLS parameter for external
     analysis.

5. **Server-specific isolation.** Deep server semantics live in
   server-specific parsers, helpers, and rule packs. The general
   pipeline does not need to know how each server merges its
   configuration.

6. **Findings are separate from issues.** A security finding and a
   technical analysis issue are different things and are kept
   separate at the model and report level.

## 4. Local analysis pipeline

```
input config -> source discovery -> parse -> include/inheritance
   -> effective config -> normalization -> rule execution -> result
```

1. **Input config.** The user passes the main configuration file or
   the root configuration source.

2. **Source discovery.** The analyzer builds a load context: the full
   set of files that were read and the include edges between them.

3. **Parsing.** A server-specific parser builds an AST or an
   equivalent structured model.

4. **Include / inheritance resolution.** For text-based servers the
   `include` directives are expanded; for IIS the inheritance chain
   between configuration files is reconstructed.

5. **Effective configuration.** Built where a flat AST is not enough:
   - Apache — `.htaccess`, `AllowOverride`, `VirtualHost`,
     `Location`, header merge semantics;
   - Lighttpd — global directives plus conditional scopes;
   - IIS — `machine.config` → `applicationHost.config` →
     `web.config`, plus `<location>` inheritance.

6. **Minimal normalization.** Server-specific representations are
   converted to a small shared model that contains only the entities
   used by universal rules.

7. **Rule execution.** Two layers run in turn:
   - server-specific rules over the AST or effective configuration;
   - universal rules over the normalized model.

8. **Reporting.** The analyzer returns an `AnalysisResult` that
   feeds the report layer.

## 5. External analysis pipeline

```
target -> port discovery -> HTTP/HTTPS probing -> TLS enrichment
   -> fingerprinting -> sensitive-path probing -> rule execution
   -> result
```

1. Target parsing and (optional) port discovery.
2. HTTP and HTTPS probing with `HEAD` → `GET` fallback and a
   separate `OPTIONS` flow.
3. TLS enrichment: negotiated protocol and cipher, actively probed
   supported TLS versions, certificate chain completeness, SAN
   extraction.
4. Fingerprinting from response headers, default error pages, and
   reactions to deliberately malformed requests.
5. Sensitive-path probing.
6. External rule execution against the collected observations.
7. Reporting through the same result and report models used by local
   mode.

External mode reuses the result and report models, but does not
depend on the AST or effective-configuration modules of local mode.

## 6. Server-specific notes

### 6.1 Nginx

- Text-based parser with `include` expansion.
- AST-first analyzer.
- Supports glob patterns, cycle detection, and source location
  tracking on every directive.
- Adds a read-only effective-scope graph over the expanded AST for
  `main`/`http`/`server`/`location`/`if in location`/`limit_except`
  inheritance work without introducing a second parser.
- Policy-gated reverse-proxy header evaluation resolves effective
  request-header replacement and response hide/pass semantics per
  supported upstream family while preserving directive source spans.

### 6.2 Apache

Apache configuration has two layers:

- The main configuration file plus its `Include` /
  `IncludeOptional` files.
- Distributed overrides through `.htaccess`.

The Apache analyzer handles both:

- `.htaccess` discovery from `Directory` blocks and `DocumentRoot`;
- `AllowOverride` filtering of `.htaccess` directives;
- Effective helpers for `VirtualHost`, `Location`, and
  `LocationMatch`;
- `ServerName` and `ServerAlias` applicability;
- Merge semantics for cumulative `Header` directives;
- Per-`VirtualHost` analysis contexts and per-context normalization.

### 6.3 Lighttpd

- Parser builds a structured model that preserves conditional
  blocks.
- Effective configuration keeps global directives and conditional
  scopes separate.
- Targeted analysis can take a request-like context, for example a
  specific `host`, into account.
- `include_shell` is safe by default: skipped with a warning.
  This intentionally differs from real lighttpd startup behavior,
  which executes `include_shell`; explicit execution is opt-in via
  `--execute-shell`.

### 6.4 Microsoft IIS

- XML parsing through `defusedxml` produces a document plus
  structured sections.
- Effective configuration restores the inheritance chain
  `machine.config` → `applicationHost.config` → `web.config` and
  the `<add>` / `<remove>` / `<clear>` collection semantics.
- Result metadata records the origin chain and the inheritance
  chain.
- TLS protocol and cipher settings often live outside the XML
  configuration, in the Windows SChannel registry. On Windows, the
  IIS analyzer reads local SChannel settings by default and records
  the host name in the TLS source metadata. For copied configs or
  offline review, `--tls-registry <path>` can supply a JSON SChannel
  export from the target host; `--no-tls-registry` disables live
  registry enrichment.

## 7. Normalization

Normalization does not try to collapse all four servers into one
common abstraction. It only extracts entities that are directly
comparable across servers:

- listen points;
- TLS-related intent and settings;
- security headers;
- access-policy markers;
- server-identification disclosure.

Per-server normalizers live in
`src/webconf_audit/local/normalizers/`. Universal rules consume the
resulting `NormalizedConfig`. Unknown values stay `None`, and the
corresponding universal rules stay silent — the goal is to avoid
false positives caused by missing data.

## 8. Rule system

The rule system is built around a centralized registry.

Key elements:

- `RuleMeta` — metadata describing a rule;
- `RuleEntry` — `RuleMeta` plus the callable that implements the
  rule;
- `RuleRegistry` — catalog of all known rules and the executable
  store;
- `@rule` — decorator used to register modular rules;
- `ensure_loaded(...)` — lazy package loader that imports rule
  modules only when needed;
- `register_meta(...)` — registers metadata for catalog entries
  that do not have an executable implementation (used for
  meta-only external rules).

Every `RuleMeta` also carries a `severity_profile` object. The profile
records impact, exposure, exploitability, confidence, and context
dependency for the rule's default severity. The methodology is
documented in [severity-methodology.md](severity-methodology.md), and
`list-rules --format json` exposes the profile for tooling.

Current catalog: 472 rules total.

| Category | Rules |
|----------|------:|
| Local — Nginx | 96 |
| Local — Apache | 87 |
| Local — Lighttpd | 50 |
| Local — IIS | 53 |
| Universal (local) | 14 |
| External | 172 |

### 8.1 Opt-in tags

The registry treats a small set of tags as **opt-in**: rules carrying
them are excluded from default analyzer runs and only included when the
caller explicitly opts in. Currently `OPT_IN_TAGS = {"policy-review"}`.

`policy-review` rules surface configuration choices that depend on
manual operator judgment (default log-format selection, rate-limit
value review, CSP policy review, IIS logging field selection, and
Nginx HTTP/3 / `Alt-Svc` consistency review). They all use
`severity="info"` and are activated via the
`--enable-policy-review` flag on every `analyze-*` command. The opt-in
contract is enforced by `rule_registry.rules_for(...,
include_opt_in_tags=...)` and threaded through every server runner and
`analyze_*_config()` entry point.

The `list-rules --tag policy-review` command always surfaces these
rules so users can discover them.

### 8.2 Standards mapping integrity

Every standards mapping is represented by a typed `StandardReference`.
Mappings with `origin="declared"` were reviewed against the exact referenced
edition. Automatically aligned mappings use `origin="derived"`, remain in the
secondary tier, and record both `derived_from_standard` and
`derived_from_reference`. For example, the OWASP Top 10:2025 categories
generated from reviewed 2021 mappings remain visible for filtering and
reporting without being presented as independently reviewed evidence.

`src/webconf_audit/standard_catalog.py` contains the bounded catalog of
canonical OWASP Top 10, ASVS, and PCI DSS identifiers used by counted coverage
claims. `src/webconf_audit/crosswalk_integrity.py` validates those identifiers,
mapping provenance, notes for partial or related evidence, duplicate
cross-tier references, and counted claims. Validation is deterministic and
offline: authoritative URLs are metadata and are never fetched during
analysis or release checks.

The rule registry remains the source of rule-to-standard evidence. The
Markdown coverage tracker is only a temporary counted-claim adapter until the
machine-readable ledger planned for the next follow-up. A derived, partial, or
related reference cannot independently justify `full` coverage, and a coverage
assessment never suppresses a `Finding`.

## 9. Reporting model

Local and external modes share the same result model:

- `Finding` — a security issue.
- `AnalysisIssue` — a technical warning or problem encountered
  during analysis.
- `AnalysisResult` — the result of one analyzer run.

The shared report layer adds:

- `ReportData` — aggregated results from one or more analyzer runs.
- `ReportSummary` — totals by severity, mode, and server type.
- `TextFormatter` — human-readable output.
- `JsonFormatter` — machine-readable output.

Policy-aware analyzers may also attach versioned `control_assessments`
to `AnalysisResult` when, and only when, an explicit audit policy asks
for analyzer-native control evaluation. These records remain separate
from `Finding` and `AnalysisIssue`, and the standalone `assess`
command remains the only component that derives target-level control
statuses from the analysis report plus the coverage ledger.

Reporting features:

- findings sorted by severity;
- issues sorted by level;
- `--format text|json` on every `analyze-*` command;
- universal rule findings are suppressed when a more specific
  server-specific rule has already reported the same issue at the
  same location.

## 10. Known limitations

- Lighttpd analysis is intentionally conservative; not all
  documented condition operators or `else if` chains are modeled.
- IIS local analysis can enrich TLS protocol and cipher visibility
  from the local Windows SChannel registry or an explicit JSON export.
  Missing registry keys remain "unknown" because effective OS defaults
  depend on the Windows version.
- The Nginx tokenizer supports both double- and single-quoted directive
  arguments. Single-quoted values follow the same un-escaping rules as
  double quotes (see `tests/test_nginx_tokenizer.py`).
