# Policy-Review Coverage Reclassification Design

Date: 2026-06-11

## Context

The control-source tracker currently preserves the conservative coverage
snapshot used in the pre-diploma report. Several CIS NGINX and CIS Apache
items are marked `not-full` even though the project already verifies a real,
narrower part of the requirement. One CIS NGINX item, HTTP/3 and `Alt-Svc`,
does not have a project signal but can be represented honestly as an
operator-review item. IIS FTP remains outside the implemented HTTP
configuration analyzers.

This change is the second coverage-focused pull request. It separates three
concerns that must not be conflated:

1. The source of an executable rule remains its registry category:
   `local`, `external`, or `universal`.
2. The finding priority remains its severity:
   `critical`, `high`, `medium`, `low`, or `info`.
3. The strength of evidence against a control-source item is documented as
   `full`, `partial`, `policy-review`, `uncovered`, or `excluded`.

`policy-review` is therefore not a new registry category and not a sixth
severity level. It remains an opt-in rule tag supported by the existing
registry, analyzer APIs, CLI flag, severity calibration, and rule-listing
interface.

## Goals

- Reclassify existing narrower evidence for seven CIS NGINX items and two CIS
  Apache items from `not-full` to `partial`.
- Add one opt-in Nginx review rule for CIS NGINX v3.0.0 section 4.1.12,
  covering the consistency of HTTP/3 listeners and `Alt-Svc` advertisement.
- Represent that item as `policy-review`, separately from full and partial
  coverage.
- Keep IIS FTP sections 6.1 and 6.2 applicable but `uncovered`.
- Update coverage documentation so that full-coverage percentages remain
  conservative and reproducible.
- Preserve all default analyzer behavior.

## Non-Goals

- Do not create a new rule category or severity value.
- Do not enable policy-review findings by default.
- Do not add HTTP/3 network negotiation, QUIC packet inspection, or an
  external HTTP/3 client.
- Do not claim that the presence of an `Alt-Svc` header proves correct HTTP/3
  operation.
- Do not add IIS FTP parsing or FTP runtime probes.
- Do not promote partial or policy-review evidence into the full-coverage
  numerator.
- Do not change the denominator of any control source in this pull request.

## Coverage Status Model

The item-level tracker will use these states:

| Status | Meaning | Included in full numerator |
| --- | --- | --- |
| `full` | Project evidence covers the counted requirement within the documented analysis boundary. | Yes |
| `partial` | A real, testable signal covers a narrower part of the requirement, but additional deployment, runtime, host, or policy evidence is needed. | No |
| `policy-review` | An opt-in rule surfaces configuration facts that require operator judgment and cannot be classified as an unconditional defect. | No |
| `uncovered` | The item is applicable to the stated source calculation but the project has no implemented evidence for it. | No |
| `excluded` | The item is outside the denominator because it belongs to an explicitly excluded analysis boundary. | No |

For each source:

```text
full coverage percentage = full items / applicable items * 100
```

The following invariant must hold:

```text
applicable = full + partial + policy-review + uncovered
```

`excluded` items are documented but are not part of `applicable`.

## Reclassification

### CIS NGINX Benchmark v3.0.0

The applicable count remains 15 and the full count remains 7.

| Counted item | New status | Basis |
| --- | --- | --- |
| Section 2.5.4 reverse-proxy disclosure | `partial` | Existing header and status behavior checks verify narrower disclosure signals, while complete proxy-header semantics remain unmodeled. |
| Section 3.1 access log format | `partial` | Existing rules verify log presence, named formats, required fields, and expose the default format for opt-in review; the final JSON/SIEM policy remains operator-specific. |
| Section 3.3 error log level | `partial` | Existing rules detect missing or excessively restrictive logging, while the preferred operational level depends on the deployment. |
| Section 4.1.2 trusted certificate chain | `partial` | External certificate probes observe served-chain defects, but a local certificate path alone cannot prove every deployed chain. |
| Section 4.1.12 HTTP/3 and `Alt-Svc` | `policy-review` | A new opt-in rule will surface HTTP/3 listener and effective `Alt-Svc` state for operator review. |
| Section 5.1.1 sensitive locations | `partial` | Existing sensitive-scope rules cover a maintained baseline, while business-specific paths require an operator-supplied catalog. |
| Sections 5.2.4 and 5.2.5 connection and rate-limit values | `partial` | Existing rules verify presence and structure; numeric suitability depends on workload and capacity. |
| Sections 5.3.2 and 5.3.3 CSP and Referrer-Policy quality | `partial` | Existing rules verify baseline header posture and expose selected values for review; complete policy semantics depend on the application. |

The resulting ledger is:

| Applicable | Full | Partial | Policy review | Uncovered | Full coverage |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 15 | 7 | 7 | 1 | 0 | 46.7% |

### CIS Apache HTTP Server 2.4 Benchmark v2.3.0

The applicable count remains 19 and the full count remains 17.

| Counted item | New status | Basis |
| --- | --- | --- |
| Sections 2.1-2.9 module minimization | `partial` | The project inventories visible `LoadModule` directives and detects selected risky modules; package/build composition and the deployment's approved module set remain external policy. |
| Sections 4.1-4.2 authorization posture | `partial` | The effective configuration model resolves current `Require`, legacy allow/deny, and inherited authorization signals; proving a server-wide business authorization policy requires deployment context. |

The resulting ledger is:

| Applicable | Full | Partial | Policy review | Uncovered | Full coverage |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 19 | 17 | 2 | 0 | 0 | 89.5% |

### CIS Microsoft IIS 10 Benchmark v1.2.1

FTP sections 6.1 and 6.2 remain applicable and `uncovered`. The project
analyzes IIS HTTP configuration and Windows SChannel evidence; it does not
parse IIS FTP authorization, logon, or channel-encryption configuration.
Keeping FTP in the denominator makes the scope limitation visible instead of
inflating coverage by exclusion.

The ledger remains:

| Applicable | Full | Partial | Policy review | Uncovered | Full coverage |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 8 | 1 | 0 | 1 | 80.0% |

The single partial item is the grouped SChannel TLS item. The single uncovered
item is the grouped FTP item.

## HTTP/3 and Alt-Svc Review Rule

### Identity and Metadata

- Rule ID: `nginx.http3_alt_svc_review`
- Registry category: `local`
- Server type: `nginx`
- Severity: `info`
- Required tag: `policy-review`
- Additional tags: `http3`, `headers`, `tls`
- Primary mapping: CIS NGINX Benchmark v3.0.0 section 4.1.12
- Mapping strength: `partial`

The registry's standard-reference strength is `partial` because the rule
observes only configuration evidence. The item-level tracker status is
`policy-review` because interpreting that evidence requires operator
judgment. These values describe different dimensions and are not competing
coverage labels.

The rule follows the existing Nginx policy-review implementation pattern and
is loaded by the existing Nginx rule package. It uses the current
`--enable-policy-review` path; no new CLI option is introduced.

### Detection Scope

The rule examines each Nginx `server` block and selects only blocks whose
`listen` directives contain the `quic` parameter. A normal `listen 443 ssl`
block is not selected and produces no finding. The rule also resolves the
effective `http3 on|off` directive for the selected block. In current Nginx
semantics, `http3` is enabled by default and is separate from the `quic`
listener parameter.

The implementation is grounded in the official Nginx HTTP/3 module
configuration model:
https://nginx.org/en/docs/http/ngx_http_v3_module.html

For each selected server block, the rule resolves effective `add_header`
directives at the `server`, nested `location`, and `if in location` response
scopes. The rule models standard replacement inheritance and the
`add_header_inherit on|off|merge` modes introduced in Nginx 1.29.3. This is
implemented locally in the HTTP/3 review rule so the broader behavior of
existing header rules does not change in this pull request.

The rule emits one finding per selected server block:

- If effective `http3 off` disables protocol negotiation, the finding reports
  that state together with the observed `Alt-Svc` state.
- If effective `Alt-Svc` headers are present, the finding reports every
  configured value, its source file and line, and the response scopes where
  that directive is effective.
- If no effective `Alt-Svc` header is present in any reviewed response scope,
  the finding reports the missing advertisement and asks the operator to
  verify whether clients are expected to discover HTTP/3 through another
  supported mechanism or whether an `Alt-Svc` header should be configured.
- If only some response scopes lack `Alt-Svc`, the finding lists those scopes
  without treating the header as globally absent.

This is deliberately a review finding in both cases. Static configuration can
show the listener and header text, but it cannot prove that UDP reachability,
TLS/QUIC negotiation, intermediary behavior, client discovery, or even the
required Nginx build module is present in the deployed environment.

### Finding Location and Deduplication

The finding location points to the first `listen` directive that establishes
the selected HTTP/3 scope. Each observed `Alt-Svc` directive retains its own
source file, line, and value in the description so headers loaded from include
files remain unambiguous.

Only one finding is emitted for a server block, even if it contains multiple
QUIC listeners or repeated `Alt-Svc` directives. Separate server blocks remain
separate review scopes.

### Default Behavior

The rule is excluded from:

- default Nginx analyzer runs;
- default registry `rules_for(...)` results;
- ordinary CI failure decisions.

It is included when the caller passes `enable_policy_review=True` or the user
runs an Nginx analysis with `--enable-policy-review`. Its severity remains
`info` after calibration because the existing severity logic pins
`policy-review` rules to informational priority.

The rule remains discoverable through:

```text
list-rules --tag policy-review
```

## Documentation Changes

Implementation must update the following documentation in one consistent
change:

- `docs/control-source-coverage-tracker.md`
  - add `policy-review` and `uncovered` to the status vocabulary;
  - replace the seven Nginx and two Apache `not-full` rows;
  - record the HTTP/3 item as `policy-review`;
  - keep IIS FTP as `uncovered`;
  - show the reconciled ledgers.
- `docs/benchmarks-covering.md`
  - replace the broad `Not fully covered` presentation with explicit
    `Partial`, `Policy review`, and `Uncovered` columns;
  - preserve every full-coverage percentage.
- `docs/rule-coverage.md`
  - add the new rule and its CIS mapping;
  - describe the mapping as partial/review evidence, not full compliance.
- `docs/standards-roadmap.md`
  - mark the HTTP/3 configuration-review signal as implemented;
  - retain runtime HTTP/3 validation as a future or excluded deeper layer.
- `docs/architecture.md`
  - update the enumerated policy-review rule count and list if present.

Any generated rule inventory or count assertion affected by the added rule
must be regenerated or updated through the repository's existing workflow.

## Test Design

### Rule Behavior

Tests will cover:

1. `listen 443 quic` without an effective `Alt-Svc` header produces one
   review finding when policy review is enabled.
2. A QUIC listener with an effective server-level `Alt-Svc` header produces
   one review finding containing the observed value.
3. A QUIC listener with effective `http3 off` produces one review finding
   that reports disabled HTTP/3 negotiation.
4. A QUIC listener inherits an HTTP-level `Alt-Svc` header when no
   server-level `add_header` directives replace the inherited set.
5. A server-level `add_header` set without `Alt-Svc` replaces an inherited
   HTTP-level `Alt-Svc`, and the finding reports the effective header as
   missing.
6. A location-level `Alt-Svc` header is reported with its response scope.
7. `add_header_inherit merge` retains inherited `Alt-Svc` values alongside
   local headers, while `off` cancels inherited values.
8. Multiple effective `Alt-Svc` directives are all reported in one finding.
9. Header directives loaded from include files retain their file and line.
10. A literal empty `Alt-Svc` value is treated as absent because Nginx does
    not emit a response header with a zero-length value.
11. A regular TLS listener without `quic` produces no finding.
12. Multiple qualifying directives in one server block are deduplicated.
13. Separate qualifying server blocks produce separate findings with their
   own source locations.

### Opt-In Contract

Tests will also verify:

- the rule is absent from default analyzer results;
- the rule appears when `enable_policy_review=True`;
- the registry excludes it by default and includes it for the
  `policy-review` opt-in tag;
- its metadata has severity `info`, category `local`, server type `nginx`,
  and tag `policy-review`;
- `POLICY_REVIEW_RULE_IDS` contains the new rule and the exact registry set
  still matches the test list;
- the CLI's existing `--enable-policy-review` path activates the rule without
  adding a new option.

### Documentation and Regression Checks

The implementation plan must include:

- focused Nginx rule tests;
- the complete policy-review test module;
- rule metadata and standards-mapping tests;
- documentation consistency or rule-inventory checks;
- the project's full test suite.

## Acceptance Criteria

The pull request is complete when all of the following are true:

1. `nginx.http3_alt_svc_review` implements the behavior in this design.
2. Default analyzer output is unchanged for users who do not opt in.
3. Policy-review output identifies the qualifying server block and observed
   effective `Alt-Svc` state.
4. The coverage tracker reports Nginx as 7 full, 7 partial, 1 policy-review,
   and 0 uncovered out of 15 applicable items.
5. The coverage tracker reports Apache as 17 full and 2 partial out of 19
   applicable items.
6. IIS FTP remains 1 uncovered grouped item and is not silently excluded.
7. Full-coverage percentages remain 46.7% for Nginx, 89.5% for Apache, and
   80.0% for IIS.
8. No partial or policy-review item is counted as full coverage.
9. All focused and full regression tests pass.
