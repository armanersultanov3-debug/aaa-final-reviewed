# Nginx Logging Policy Design

Date: 2026-06-12
Status: proposed
Sequence: follow-up 06 of 14

## Status and Dependencies

This is the design for followup-06. It converts the operator-dependent gaps
behind CIS NGINX sections 3.1 and 3.3 into explicit policy-backed
assessments.

The implementation depends on:

- followup-03 for versioned, strictly validated `AuditPolicy`;
- followup-04 for `ControlAssessment` and the shared `pass`, `fail`,
  `not-applicable`, and `indeterminate` statuses used by this evaluator;
- followup-05 for the source-aware Nginx effective-scope graph;
- PR #9 for the distinction between built-in findings, opt-in policy review,
  and coverage evidence.

This design does not redefine those foundations. If their final module or
field names differ, the implementation must preserve the behavior specified
here.

## Decision Summary

Add an optional `nginx.logging` policy with separate access-log and error-log
profiles. Resolve effective `access_log`, `log_format`, and `error_log`
configuration at every material Nginx scope, compare it with the declared
destination, format, field, condition, and severity requirements, and emit
`ControlAssessment` records.

The evaluator remains static and configuration-bounded:

- it can prove which directives and named formats are effective;
- it can classify file, syslog, stderr, memory, and variable destinations;
- it can parse Nginx variables used by a format;
- it cannot prove file permissions, retention, clock synchronization, SIEM
  ingestion, alerting, or successful delivery.

Those external properties remain partial or indeterminate evidence and must
not be silently promoted to pass.

## Current Evidence and Rules

The repository currently provides these Nginx findings:

- `nginx.missing_access_log` checks server-level effective `access_log`
  presence from `http` and `server`, but not location-level overrides.
- Its current implementation treats any effective `access_log off` as
  disabling logging, without a reusable representation of multiple logs or
  conditional logs.
- `nginx.missing_log_format` checks references to undefined named formats and
  recognizes Nginx's built-in `combined` format.
- `nginx.log_format_missing_fields` parses variables in used named formats
  and checks a built-in set of timestamp, client, request, status, user-agent,
  request ID, forwarded chain, upstream timing, and TLS fields.
- `nginx.access_log_uses_default_format` is an opt-in `policy-review` finding
  for the built-in `combined` format.
- `nginx.missing_error_log` checks explicit effective configuration across
  `main`, `http`, and `server`; it does not model location overrides or the
  Nginx default destination as a policy choice.
- `nginx.error_log_too_restrictive` flags `/dev/null` and thresholds
  `error`, `crit`, `alert`, or `emerg`.
- The coverage tracker marks CIS NGINX section 3.1 and section 3.3 as
  `partial`, because the correct format, destination, and error threshold are
  deployment policy.

The current AST preserves directives and source spans after include
expansion. It does not currently expose effective logging objects, named
format definitions, condition classification, or scope completeness in a
single model.

## Exact Control Rows

The following rows define the documentation and mapping boundary:

| Source | Row | Exact row text | Static evidence in this design |
| --- | --- | --- | --- |
| CIS NGINX Benchmark v3.0.0 | 3.1 | Ensure detailed logging is enabled | Effective access-log enablement, selected format, required fields, escaping mode, and approved destinations. |
| CIS NGINX Benchmark v3.0.0 | 3.3 | Ensure error logging is enabled and set to the info logging level | Effective error-log destinations and severity thresholds. |
| OWASP ASVS 5.0.0 | V16.2.1, L2 | Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens. | Required Nginx access-log variables and groups. |
| OWASP ASVS 5.0.0 | V16.2.2, L2 | Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions. | Timestamp variable and explicit offset can be checked; clock synchronization cannot. |
| OWASP ASVS 5.0.0 | V16.2.3, L2 | Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory. | Approved destination inventory. |
| OWASP ASVS 5.0.0 | V16.2.4, L2 | Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format. | Format name, escaping mode, and required correlation fields; actual processor ingestion remains external. |
| OWASP ASVS 5.0.0 | V16.2.5, L2 | Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially. | Forbidden raw Nginx variables can be detected; application-level transformations cannot be proven. |
| OWASP ASVS 5.0.0 | V16.3.4, L2 | Verify that the application logs unexpected errors and security control failures such as backend TLS failures. | Error-log threshold is related evidence only; event completeness is not proven. |
| OWASP ASVS 5.0.0 | V16.4.1, L2 | Verify that all logging components appropriately encode data to prevent log injection. | `log_format escape=json` and known escaping choices are configuration evidence. |
| OWASP ASVS 5.0.0 | V16.4.3, L2 | Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised. | A syslog destination is only related configuration evidence; transport security and logical separation remain external. |
| OWASP Top 10:2021 | A09:2021 | Security Logging and Monitoring Failures | Primary current repository category. |
| OWASP Top 10:2025 | A09:2025 | Security Logging and Alerting Failures | Current-edition companion mapping. |
| OWASP Cheat Sheet Series | Logging Cheat Sheet | Logging Cheat Sheet | Primary companion guidance. |

ASVS rows V16.2.2, V16.2.4, V16.2.5, V16.3.4, V16.4.1, and V16.4.3
must remain `partial` when mapped from static Nginx evidence. The evaluator
must not claim application event completeness, secure transport, retention,
or alerting.

## Official Nginx Rules to Model

- `access_log` is valid in `http`, `server`, `location`, `if in location`, and
  `limit_except`.
- Several access logs may be declared at one configuration level.
- `access_log off` cancels access logs on the current level.
- If no format is specified, Nginx uses the built-in `combined` format.
- `if=condition` skips a log when the evaluated condition is empty or `0`.
- Requests are logged in the context of the location where processing ends,
  which can differ after an internal redirect.
- `log_format` is valid only in `http`.
- `escape=default`, `escape=json`, and `escape=none` have different injection
  properties.
- `error_log` is valid in `main`, `http`, `server`, and `location` for the
  HTTP analysis boundary.
- Several error logs may be declared at one level.
- Error levels are ordered:
  `debug`, `info`, `notice`, `warn`, `error`, `crit`, `alert`, `emerg`.
  Choosing a threshold records that level and all more severe levels.
- If no main-level file is explicitly configured, Nginx uses its compiled
  default error log.

Where public directive documentation does not spell out merge behavior, the
implementation must mirror the corresponding Nginx Open Source merge
function and lock the behavior with tests.

## Gaps to Close

1. Location and `if in location` access-log overrides are not currently
   represented as effective logging scopes.
2. A single server-level check can miss a sensitive location containing
   `access_log off`.
3. Multiple destinations and formats at one level are flattened into boolean
   presence.
4. Conditional logging is not classified, so a syntactically present log can
   be effectively disabled for relevant requests.
5. The built-in `combined` format is exposed only through an opt-in review
   finding and cannot be compared with an operator contract.
6. Required field groups are hard-coded rather than policy-defined.
7. Destinations are not compared with an approved log inventory.
8. `escape=none` and raw sensitive variables are not policy-evaluated.
9. Error-log thresholds are hard-coded instead of supporting an approved
   range.
10. Missing includes can leave a partial logging tree that appears to satisfy
    policy.
11. Current findings and future control outcomes need a non-duplicating
    relationship.

## Goals

- Resolve effective access and error logging at material Nginx scopes.
- Preserve all same-level destinations rather than selecting one.
- Resolve named and built-in access-log formats.
- Parse format variables and escaping mode without interpreting log output as
  JSON.
- Support policy-defined required field groups, forbidden variables, approved
  destinations, and error thresholds.
- Represent conditional logging honestly.
- Emit deterministic, source-aware control assessments.
- Preserve existing findings and default behavior without policy.
- Keep coverage claims conservative and explicit.

## Non-Goals

- Do not read log files or contact syslog/SIEM endpoints.
- Do not verify rotation, retention, permissions, disk capacity, or
  tamper-resistance.
- Do not verify NTP, clock synchronization, or host time-zone configuration.
- Do not prove that application authentication, authorization, or business
  events are logged.
- Do not evaluate arbitrary `map`, njs, Lua, or application logic used in an
  `if=` logging condition.
- Do not simulate internal redirects to determine the final runtime location.
- Do not require JSON universally; format requirements remain policy.
- Do not change existing finding severities or CIS coverage percentages in
  this followup.

## Foundation Contract

The evaluator consumes:

```text
AuditPolicy
  schema_version
  nginx.logging | null
```

It emits assessments with at least:

- `policy_section: "nginx.logging"`
- `profile_id`
- `server_scope_id`
- `logging_scope_id`
- `logging_kind: "access" | "error"`
- effective destinations;
- selected formats and format-definition sources;
- required, present, and missing field groups;
- condition classification;
- completeness and external-evidence notes.

The result belongs in `AnalysisResult.control_assessments`, never in
`Finding.metadata`.

## Proposed Models

### Access Log Destination

```python
class AccessLogDestination:
    destination_kind: Literal[
        "file", "syslog", "stderr", "variable_path", "off", "unknown"
    ]
    raw_path: str
    format_name: str
    options: tuple[str, ...]
    condition: str | None
    condition_kind: Literal[
        "unconditional", "constant_true", "constant_false", "dynamic"
    ]
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str
    origin: Literal["explicit", "inherited", "nginx_default"]
```

`access_log off` is represented as a state, not as a destination mixed with
enabled logs.

### Log Format Definition

```python
class LogFormatDefinition:
    name: str
    escape_mode: Literal["default", "json", "none"]
    raw_tokens: tuple[str, ...]
    variables: frozenset[str]
    source: SourceSpan | None
    origin: Literal["explicit", "nginx_builtin"]
```

The built-in `combined` format is an explicit model object with the official
Nginx variable set. `compatible` is supported only if the current analyzer
already treats it as built in and tests document the intended compatibility.

### Error Log Destination

```python
class ErrorLogDestination:
    destination_kind: Literal[
        "file", "syslog", "stderr", "memory", "null_device", "unknown"
    ]
    raw_path: str
    threshold: Literal[
        "debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"
    ]
    json_mode: bool
    source: SourceSpan | None
    declared_scope_id: str
    effective_scope_id: str
    origin: Literal["explicit", "inherited", "nginx_default"]
```

The optional `json` error-log parameter is modeled as a capability, not
required by default and not assumed available in every Nginx edition.

### Effective Logging Scope

```python
class EffectiveLoggingScope:
    scope_id: str
    access_state: Literal["enabled", "off", "unknown"]
    access_logs: tuple[AccessLogDestination, ...]
    error_logs: tuple[ErrorLogDestination, ...]
    complete: bool
    indeterminate_reasons: tuple[str, ...]
```

Material scopes are:

- every `server`;
- every descendant `location`, `if in location`, or `limit_except` that
  declares access-log behavior;
- every descendant `location` that declares error-log behavior;
- every descendant scope explicitly selected by a policy profile.

This avoids emitting duplicate inherited assessments for every AST block
while still testing every override boundary.

## Nginx Scope and Inheritance Semantics

### Access Logs

For a material scope:

1. If the scope declares effective current-level `access_log off`, the state
   is `off`.
2. If the scope declares one or more enabled `access_log` directives, those
   current-level logs form the effective set.
3. Otherwise, inherit the parent effective set.
4. At the `http` root with no explicit access log, model Nginx's documented
   default `logs/access.log combined`.
5. Keep multiple same-level logs in declaration order.

Exact parser behavior for mixing `access_log off` and enabled logs at one
level must be validated against Nginx. If the configuration would be rejected
by Nginx, the analyzer must not invent a merge result; the assessment is
`indeterminate` and the configuration issue is preserved.

An `if in location` creates a conditional child branch. Its access-log
configuration does not replace the parent location for requests that do not
take the branch.

### Conditional Access Logging

- No `if=` parameter means unconditional.
- A literal empty value or `0` is `constant_false`.
- A statically non-empty, non-zero literal is `constant_true`.
- Any variable or expression is `dynamic`.
- Version 1 does not evaluate `map` output or arbitrary conditions.

Policy decides whether dynamic conditions are allowed. Even when allowed, the
assessment evidence must say that logging coverage depends on runtime values.

### Named Formats

`log_format` definitions are collected only from `http` context after include
expansion. An undefined format is incomplete evidence and should continue to
trigger the existing finding. A policy assessment depending on it is
`indeterminate`, not `fail`, because Nginx itself may reject the config before
serving traffic.

Variables are parsed from tokenized format text. Similar names such as
`$request_id_suffix` must not satisfy `$request_id`.

### Error Logs

For `main`, `http`, `server`, and `location`:

1. Use all error logs declared at the nearest configuration level that has
   any.
2. Otherwise inherit the parent set.
3. At main level with no explicit directive, represent the compiled Nginx
   default as `origin="nginx_default"` and threshold `error`.
4. A policy may require an explicit destination and therefore reject the
   compiled default.
5. Threshold comparisons use the documented severity ordering, not string
   ordering.

`error_log` inside `if in location` is not accepted as an effective source.

### Includes and Completeness

Included directives participate at their lexical expansion point and retain
their original source span. A missing, cyclic, or malformed include marks the
affected scope incomplete. A logging assessment that depends on that scope is
`indeterminate`, even if the remaining partial tree appears to satisfy the
declared policy.

## Policy Schema Fragment

```yaml
schema_version: 1
nginx:
  logging:
    profiles:
      public_web:
        applies_to:
          server_names: ["www.example.test", "api.example.test"]
          location_patterns: ["/", "/api/"]
        access:
          required: true
          allow_off: false
          conditional:
            mode: forbid
            allowed_conditions: []
          destinations:
            allowed:
              - kind: file
                path: /var/log/nginx/access.log
              - kind: syslog
                prefix: "syslog:server=logs.example.test"
            require_at_least_one_remote: false
            allow_variable_paths: false
          formats:
            allowed_names: [main_json]
            require_escape: json
            required_field_groups:
              timestamp: ["$time_iso8601"]
              client_ip: ["$remote_addr", "$realip_remote_addr"]
              identity: ["$remote_user"]
              request: ["$request"]
              status: ["$status"]
              correlation: ["$request_id", "$http_x_request_id"]
              user_agent: ["$http_user_agent"]
            forbidden_variables:
              - "$http_authorization"
              - "$cookie_session"
        error:
          required: true
          require_explicit_destination: true
          destinations:
            allowed_kinds: [file, syslog, stderr]
            forbidden_paths: ["/dev/null"]
          threshold:
            most_restrictive_allowed: info
            allow_debug: false
    unmatched_scopes: indeterminate
```

Validation requirements:

- Profile IDs are unique.
- Selectors use the bounded selector model from followup-05.
- Required field-group names are unique.
- Every required field group contains at least one exact Nginx variable.
- Forbidden variables cannot also satisfy a required group.
- Allowed destination entries are normalized and non-empty.
- `most_restrictive_allowed` is one documented Nginx severity.
- `allow_debug: false` can reject `debug` even though it is more verbose,
  because production debug logging has separate operational risk.
- `conditional.mode` is `forbid`, `allow_dynamic`, or `allow_listed`.
- Overlapping non-equivalent profiles are a policy validation error.
- Unknown keys are rejected by followup-03 strict validation.

Version 1 does not support arbitrary regular expressions over destinations,
formats, or conditions.

## Assessment Algorithm

For each material scope matched by exactly one profile:

### Access Assessment

1. Resolve effective access-log state and destinations.
2. If logging is off and the policy requires it, return `fail`.
3. If a required scope has no enabled destination, return `fail`.
4. Compare every effective destination with the approved inventory.
5. Classify every `if=` condition.
6. Resolve every referenced format.
7. Compare allowed format names, escape mode, required field groups, and
   forbidden variables.
8. Return `indeterminate` if required evidence is missing, dynamic beyond the
   policy boundary, or loaded from an incomplete scope.
9. Otherwise return `pass` only when all required predicates pass.

### Error Assessment

1. Resolve all effective error-log destinations.
2. Reject forbidden destination kinds or paths.
3. Enforce explicit-destination policy separately from Nginx defaults.
4. Compare every effective threshold with the allowed range.
5. If one same-level error log is too restrictive, the assessment fails even
   if another destination satisfies the policy, unless the policy explicitly
   defines per-destination exceptions.
6. Record unsupported `json` mode or edition-specific evidence without
   assuming availability.

Recommended control IDs:

- `cis-nginx-3.1.detailed-access-logging`
- `cis-nginx-3.3.error-log-info-level`
- `asvs-5.0.0-v16.2.3.log-destination-inventory`
- `policy.nginx.logging`

## Findings Versus Control Assessments

- Existing unconditional logging findings remain enabled by default.
- A failed operator policy is a `ControlAssessment(status=fail)`, not a new
  finding in version 1.
- Existing findings can be linked through `related_rule_ids`.
- `nginx.access_log_uses_default_format` remains available under
  `--enable-policy-review` when no explicit logging policy applies.
- When an explicit policy assesses the same format choice, the generic review
  finding should be suppressed for that scope to avoid duplicate operator
  work.
- A passing policy assessment must not suppress
  `nginx.missing_log_format` or another finding that indicates invalid
  configuration.
- Assessment status never changes finding severity.

## Default Behavior Without Policy

With no `nginx.logging` section:

- no logging control assessments are emitted;
- all existing logging findings, counts, IDs, text, ordering, and default
  opt-in behavior remain stable;
- the new effective model may be shared internally only after no-policy
  golden tests prove parity;
- no destination or format preference is assumed;
- CIS 3.1 and 3.3 remain `partial` in the tracker.

## Error and Indeterminate Handling

| Condition | Result |
| --- | --- |
| Invalid policy file or logging section | `AnalysisIssue` from followup-03; no logging assessments. |
| Root config parse failure | Existing fatal behavior; no logging assessments. |
| Missing/cyclic/malformed include affecting a scope | `indeterminate` with issue codes and known partial evidence. |
| Undefined named log format | Existing finding plus `indeterminate` assessment. |
| Dynamic `if=` condition with policy mode `forbid` | `fail`. |
| Dynamic `if=` condition with policy mode `allow_dynamic` | Continue evaluation and record a runtime-dependence note; do not claim request-by-request coverage. |
| Variable destination when variable paths are forbidden | `fail`. |
| Variable destination when allowed but not inventory-resolvable | `indeterminate`. |
| Nginx compiled default path is unknown and explicit destination is not required | `indeterminate` destination identity, while threshold may still be evaluated. |
| Edition-specific `error_log ... json` requirement cannot be proven supported | `indeterminate`. |
| Directive in illegal context | Exclude from effective semantics; attach unsupported evidence. |
| Ambiguous or Nginx-invalid same-level combination | `indeterminate`, never guessed. |

## Likely Files

- `src/webconf_audit/local/nginx/effective_scope.py` - reuse followup-05.
- `src/webconf_audit/local/nginx/logging_semantics.py` - new effective logging
  resolver.
- `src/webconf_audit/local/nginx/assessments/logging.py` - new policy
  evaluator.
- `src/webconf_audit/policy/models.py` - add the logging policy fragment.
- `src/webconf_audit/models.py` or followup-04 assessment module - integration
  only.
- Existing logging rules may consume shared helpers after parity tests:
  - `missing_access_log.py`
  - `missing_log_format.py`
  - `log_format_missing_fields.py`
  - `access_log_uses_default_format.py`
  - `missing_error_log.py`
  - `error_log_too_restrictive.py`
- `tests/test_nginx_logging_semantics.py`
- `tests/test_nginx_logging_policy.py`
- `tests/fixtures/webserver-configs/nginx/policy/logging/`

## Comprehensive Test Design

### Access-Log Scope and Inheritance

- Nginx default access log with no directive.
- Explicit `access_log` at `http`, inherited by multiple servers.
- Server-level logs replace inherited logs.
- Location-level logs replace inherited logs.
- `access_log off` at server and location.
- Multiple enabled logs at one level remain a set.
- Legal `if in location` access-log branch is separate from the parent path.
- `limit_except` access-log behavior is represented without leaking into the
  containing location.
- An illegal access-log placement is ignored and reported as unsupported.
- Included access logs at `http`, `server`, `location`, and `if in location`.
- Nested and glob includes retain deterministic order and source locations.

### Formats and Fields

- Implicit and explicit built-in `combined`.
- Named `log_format` loaded from an include.
- Undefined format produces existing finding plus indeterminate assessment.
- `escape=default`, `escape=json`, and `escape=none`.
- Required group passes when any exact alternative variable is present.
- `$request_id_suffix` does not satisfy `$request_id`.
- Braced variables such as `${request_id}` normalize correctly.
- Quoted format fragments are joined without losing variable boundaries.
- Forbidden raw authorization, cookie, and query variables fail only on exact
  variable identity.
- A masked custom variable is not assumed safe unless policy explicitly
  allows it.
- Upstream and TLS-specific field groups are evaluated only for profiles that
  require them; a static-file profile is not forced to log upstream timing.

### Conditional Logging

- No condition is unconditional.
- `if=0` and an empty literal are constant false.
- A non-zero literal is constant true.
- `if=$loggable` is dynamic.
- A `map` definition is not evaluated in version 1.
- `forbid`, `allow_dynamic`, and `allow_listed` policy modes.
- A condition on one destination does not make an unconditional sibling
  destination conditional.

### Destinations

- File, syslog, stderr, memory, `/dev/null`, and variable path
  classification.
- Exact approved file path.
- Approved syslog prefix without pretending delivery succeeded.
- Similar path prefixes do not match exact inventory entries.
- Multiple destinations include one forbidden destination and correctly fail.
- Nginx default paths are represented as defaults, not fabricated literals.

### Error Logs

- Explicit `error_log` at `main`, `http`, `server`, and `location`.
- Nearest-level set replaces inherited set according to verified Nginx merge
  behavior.
- Multiple same-level error logs are all assessed.
- Default omitted threshold is `error`.
- Every threshold in documented order is tested.
- `info` requirement rejects `notice`, `warn`, `error`, `crit`, `alert`, and
  `emerg`.
- `debug` passes verbosity but fails when production debug is forbidden.
- `/dev/null` and memory destinations exercise policy boundaries.
- `error_log` inside `if` does not affect the parent.

### Includes, Issues, and Serialization

- Missing include under one server makes that server indeterminate without
  contaminating a complete sibling server.
- Include cycle and parse error preserve issue codes.
- Evidence records both declaration and effective scope.
- Assessment ordering and JSON serialization are deterministic.
- Unknown policy keys and contradictory profile settings fail validation.

### Findings and False-Positive Boundaries

- No-policy golden results match the pre-followup analyzer.
- A public server and a deliberately unlogged health-check location can use
  distinct profiles.
- Static content is not forced to contain upstream-only fields.
- A local file destination is not claimed insecure merely because it is not
  remote unless policy requires remote logging.
- `access_log off` in an unreachable or unmatched scope does not fail an
  unrelated profile.
- The analyzer does not claim ASVS clock synchronization, retention, secure
  transmission, or SIEM processing from static directives.
- Generic default-format review is suppressed only where an explicit policy
  assessment replaces it.

## Documentation and Coverage Effects

When implementation lands:

- `docs/rule-coverage.md` should describe policy assessments separately from
  finding rules.
- `docs/control-source-coverage-tracker.md` should retain CIS 3.1 and 3.3 as
  `partial` unless the project formally adopts a static-only control boundary.
- ASVS V16 mappings must use `partial` notes that state which external
  properties are not proven.
- `docs/benchmarks-covering.md` should distinguish built-in findings from
  policy-backed results.
- `docs/architecture.md` should document effective logging scopes and
  conditional evidence.
- CLI/API docs should show one logging policy and state that no policy means no
  logging assessments.

The source coverage numerator does not change in this followup.

## Acceptance Criteria

- Access and error logging are resolved at every material legal scope.
- Includes, multiple destinations, inherited values, `off`, and `if in
  location` are covered by tests.
- Required format fields and forbidden variables use exact parsed variables.
- Error thresholds use documented severity ordering.
- Dynamic conditions and unknown destinations do not produce guessed passes.
- Existing findings remain stable without policy.
- Policy failures appear only as control assessments in version 1.
- Exact CIS, ASVS, and OWASP rows in this document are used in mappings and
  docs.
- No claim is made for SIEM delivery, retention, clock synchronization, or
  application event completeness.
- Full repository tests and generated documentation checks pass.

## Dependencies

- Followup-03 policy loader and schema versioning.
- Followup-04 assessment model, rendering, and aggregation.
- Followup-05 source-aware Nginx scope graph and completeness propagation.
- Existing include expansion and parser token fidelity.
- Official Nginx log and core module documentation plus Nginx Open Source
  merge behavior where public docs are silent.

## Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Conditional logs are treated as always enabled | Classify conditions and require explicit policy treatment. |
| A hard-coded "best" format creates false positives | Put fields, escaping, and destination inventory in policy. |
| Location overrides are missed | Assess material descendant scopes and explicit profile targets. |
| Too many duplicate assessments | Emit at server roots and divergent or explicitly targeted descendants only. |
| Static syslog configuration is mistaken for delivery proof | Record configuration evidence and keep delivery external. |
| Existing findings change during helper reuse | Require no-policy golden tests before refactoring old rules. |
| Sensitive variables are matched by substring | Parse exact Nginx variable tokens. |
| Nginx edition/version differences are ignored | Mark edition-specific requirements indeterminate unless declared and supported. |

## Rollback Plan

1. Stop registering the logging assessment evaluator.
2. Remove `nginx.logging` from the policy schema.
3. Retain the followup-05 scope graph.
4. Retain any logging resolver only if later followups use it; otherwise
   remove it with its tests.
5. Keep all existing logging findings and `policy-review` behavior.
6. Revert only docs describing policy-backed logging; keep conservative
   coverage statuses.

Assessments are derived output, so no persisted-data migration is required.

## Reviewer Checklist

- [ ] The code uses followup-03/04 contracts rather than parallel models.
- [ ] Access-log inheritance, `off`, multiple logs, and defaults match Nginx.
- [ ] `http`, `server`, `location`, `if in location`, and `limit_except`
      boundaries are tested.
- [ ] Error-log inheritance and threshold ordering are exact.
- [ ] Includes preserve evidence locations and completeness.
- [ ] Dynamic conditions are not treated as unconditional.
- [ ] Required and forbidden variables are parsed exactly.
- [ ] Destination inventory does not imply runtime delivery.
- [ ] Findings and assessments remain distinct.
- [ ] No-policy output is covered by golden regression tests.
- [ ] Exact standards rows and conservative coverage notes are present.
- [ ] The pull request remains limited to logging policy and shared semantics
      needed for it.
