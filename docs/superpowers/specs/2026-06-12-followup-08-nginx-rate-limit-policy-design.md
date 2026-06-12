# Nginx Rate-Limit Policy Design

Date: 2026-06-12
Status: proposed
Sequence: follow-up 08 of 14

## Status and Dependencies

This is the design for followup-08. It turns the operator-judgment gap behind
CIS NGINX sections 5.2.4 and 5.2.5 into route-aware, policy-backed control
assessments.

The implementation depends on:

- followup-03 for versioned and strictly validated `AuditPolicy`;
- followup-04 for `ControlAssessment`;
- followup-05 for the source-aware Nginx effective-scope graph;
- followup-07 for the bounded server/location selector and concrete URI sample
  matcher when route profiles use it;
- PR #9 for default-off policy review and conservative coverage accounting.

The feature must use those foundations rather than introduce a second policy,
route, or assessment system.

## Decision Summary

Add an optional `nginx.rate_limits` policy with:

- named request-zone and connection-zone expectations;
- route profiles that require one or more effective request and connection
  limits;
- numeric ranges for request rate, burst, delayed requests, and concurrent
  requests;
- approved key expressions;
- requirements for dry-run state, rejection status, and logging level.

Resolve Nginx `limit_req` and `limit_conn` inheritance exactly at
`http`, `server`, and `location`. Link each effective limit to its
`limit_req_zone` or `limit_conn_zone` definition in `http` context. Emit
route-scoped `ControlAssessment` results without changing existing findings
when no policy is supplied.

Version 1 is a static configuration assessment. It does not estimate real
traffic, capacity, queueing latency, distributed client identity, or whether
another proxy layer already enforces a limit.

## Current Evidence and Rules

The current Nginx rule family includes:

- `nginx.missing_limit_req` and `nginx.missing_limit_conn`, which treat any
  server-level or descendant location directive as sufficient for a server.
  A protected health-check location can therefore suppress a finding for an
  unprotected public API.
- `nginx.missing_limit_req_zone` and
  `nginx.missing_limit_conn_zone`, which verify structural presence.
- `nginx.limit_req_unknown_zone`, which detects a request limit referencing
  an undefined zone.
- `nginx.limit_req_zone_invalid_rate` and
  `nginx.limit_conn_invalid_limit`, which validate positive basic values.
- `nginx.limit_req_zone_not_per_ip` and
  `nginx.limit_conn_zone_not_per_ip`, which accept
  `$binary_remote_addr` or `$remote_addr`.
- `nginx.limit_req_zone_rate_review` and
  `nginx.limit_conn_zone_review`, which are opt-in `policy-review` findings
  because suitable values depend on workload.
- `nginx.public_autoindex_rate_limit_policy_weak`, which applies fixed
  heuristics of 120 requests per second and 100 connections to a narrow
  autoindex case.

The current utility parser supports integer `r/s` and `r/m` rates and positive
integer caps. It does not model route-specific effective sets, `burst`,
`delay`, `nodelay`, dry-run, rejection status, logging thresholds, zone memory
size, or policy-selected keys.

The coverage tracker groups CIS NGINX sections 5.2.4 and 5.2.5 as `partial`
because numeric suitability is workload-specific.

## Exact Control Rows

| Source | Row | Exact row text | Intended evidence |
| --- | --- | --- | --- |
| CIS NGINX Benchmark v3.0.0 | 5.2.4 | Ensure the number of connections per IP address is limited | Effective per-client `limit_conn_zone` and `limit_conn` policy on selected public routes. |
| CIS NGINX Benchmark v3.0.0 | 5.2.5 | Ensure rate limits by IP address are set | Effective per-client `limit_req_zone` and `limit_req` policy on selected public routes. |
| OWASP ASVS 5.0.0 | V2.4.1, L2 | Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources. | Direct static evidence that Nginx limits are configured on policy-selected routes; application effectiveness remains partial. |
| OWASP ASVS 5.0.0 | V2.4.2, L3 | Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions. | Related evidence only; generic Nginx rate limits cannot prove realistic human timing. |
| OWASP ASVS 5.0.0 | V16.3.3, L2 | Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation. | Limit rejection/delay log-level configuration is partial evidence. |
| OWASP API Security Top 10:2023 | API4:2023 | Unrestricted Resource Consumption | Primary OWASP API companion category for request and concurrency limits. |
| OWASP Top 10:2021 | A04:2021 | Insecure Design | Related category when anti-automation and resource controls are absent by design. |
| OWASP Top 10:2025 | A06:2025 | Insecure Design | Current-edition companion mapping. |
| OWASP Top 10:2021 | A05:2021 | Security Misconfiguration | Related category for incorrectly scoped or disabled Nginx limits. |
| OWASP Top 10:2025 | A02:2025 | Security Misconfiguration | Current-edition companion mapping. |
| OWASP Cheat Sheet Series | Denial of Service Cheat Sheet | Denial of Service Cheat Sheet | Companion operational guidance. |

ASVS and OWASP API mappings remain `partial`: static Nginx configuration
cannot establish application cost, distributed abuse resistance, capacity, or
business-flow correctness.

## Official Nginx Rules to Model

### Request Limits

- `limit_req_zone` is valid only in `http`.
- Its key can be text, variables, or a combination; requests with an empty key
  are not accounted.
- A zone defines shared memory size and an average request rate.
- `limit_req` is valid in `http`, `server`, and `location`.
- Several `limit_req` directives may be active at one level and all apply.
- A child inherits the parent's complete `limit_req` list if and only if the
  child defines no `limit_req` directive.
- `burst` controls the excess queue capacity.
- Without `nodelay`, excessive requests can be delayed; `delay=N` changes the
  point at which delay begins.
- `limit_req_dry_run on` counts excessive requests but does not enforce
  rejection or delay.
- `limit_req_status` defaults to 503.
- `limit_req_log_level` defaults to `error`; delay events are logged one
  level less severe than rejection events.

### Connection Limits

- `limit_conn_zone` is valid only in `http`.
- `limit_conn` is valid in `http`, `server`, and `location`.
- Several `limit_conn` directives may be active at one level and all apply.
- A child inherits the parent's complete `limit_conn` list if and only if the
  child defines no `limit_conn` directive.
- In HTTP/2 and HTTP/3, each concurrent request is counted as a separate
  connection for this module.
- `limit_conn_dry_run` defaults to `off`.
- `limit_conn_status` defaults to 503.
- `limit_conn_log_level` defaults to `error`.

The scalar companion directives use ordinary nearest-value inheritance within
their documented contexts. Directives inside `if in location` are not legal
sources for these modules and must not alter the parent result.

## Gaps to Close

1. Current presence checks are server-wide and can be satisfied by an
   unrelated protected location.
2. Current rules do not distinguish inherited lists from local replacement
   lists.
3. Multiple active zones are not represented as an effective set.
4. Zone definitions and usages are not linked into a source-aware model.
5. Per-IP is hard-coded to two exact variables and cannot express a trusted
   policy for API keys, users, tenant IDs, or composite keys.
6. Request rate, burst, delay, and nodelay are not evaluated together.
7. Dry-run can look configured while providing no enforcement.
8. Default 503 rejection can be operationally undesirable when policy
   requires 429.
9. Rejection/delay logging posture is not assessed.
10. Fixed autoindex thresholds cannot represent workload-specific profiles.
11. Includes and partial ASTs can create apparently complete but unsound
    evidence.
12. Existing policy-review findings need a precise replacement only when an
    explicit policy applies.

## Goals

- Model request and connection zones with exact parsed values and source.
- Resolve effective limit lists and scalar companions at route scopes.
- Support explicit workload profiles and route matching.
- Compare exact key expressions and numeric ranges.
- Detect dry-run, missing zones, wrong zones, overly weak or overly strict
  values according to policy.
- Preserve multiple active limits and their intersection.
- Emit deterministic assessments with complete evidence.
- Keep no-policy findings and output stable.
- Maintain conservative standards coverage.

## Non-Goals

- Do not recommend universal numeric values.
- Do not infer traffic volume, backend capacity, acceptable latency, or
  business criticality from configuration.
- Do not run load tests or observe runtime rejection behavior.
- Do not model rate limits enforced by CDN, WAF, API gateway, service mesh, or
  application code.
- Do not prove `$remote_addr` represents the original client behind an
  unverified proxy chain.
- Do not support third-party modules such as `limit_req2`, Lua limiters, or
  commercial key-value rate limiting in version 1.
- Do not execute `map`, njs, or arbitrary variables to prove key cardinality.
- Do not treat an invalid Nginx directive in `if` as effective.
- Do not promote CIS 5.2.4 or 5.2.5 to full coverage by default.

## Foundation Contract

The evaluator consumes:

```text
AuditPolicy
  schema_version
  nginx.rate_limits | null
```

Every assessment includes:

- `policy_section: "nginx.rate_limits"`
- `profile_id`
- `server_scope_id`
- `route_scope_id` and optional sample URI;
- effective request and connection limits;
- referenced zone definitions;
- effective dry-run, status, and log-level values;
- normalized numeric comparisons;
- completeness and unsupported evidence.

The output is serialized by followup-04 in
`AnalysisResult.control_assessments`.

## Proposed Models

### Normalized Rate

```python
class RequestRate:
    requests: int
    period_seconds: int

    @property
    def requests_per_second(self) -> Fraction: ...
```

Use rational arithmetic, not binary floating point, so `60r/m` compares
exactly with `1r/s`.

### Zone Definitions

```python
class LimitReqZone:
    name: str
    key_tokens: tuple[str, ...]
    normalized_key: str
    size_bytes: int
    rate: RequestRate
    sync: bool
    source: SourceSpan


class LimitConnZone:
    name: str
    key_tokens: tuple[str, ...]
    normalized_key: str
    size_bytes: int
    source: SourceSpan
```

Duplicate zone names with incompatible definitions are invalid or
indeterminate evidence, never last-one-wins.

### Effective Limit Usages

```python
class EffectiveLimitReq:
    zone_name: str
    burst: int
    delay: int
    nodelay: bool
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str


class EffectiveLimitConn:
    zone_name: str
    connections: int
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str
```

Default request values are represented explicitly:

- `burst=0`;
- no `nodelay`;
- default delay behavior as defined by Nginx.

An invalid or contradictory option combination remains unsupported evidence
and should also preserve any existing structural finding.

### Effective Rate-Limit Scope

```python
class EffectiveRateLimitScope:
    scope_id: str
    request_limits: tuple[EffectiveLimitReq, ...]
    connection_limits: tuple[EffectiveLimitConn, ...]
    request_dry_run: bool
    connection_dry_run: bool
    request_status: int
    connection_status: int
    request_log_level: str
    connection_log_level: str
    complete: bool
    indeterminate_reasons: tuple[str, ...]
```

### Workload Profile

```python
class RateLimitProfile:
    profile_id: str
    selector: RouteSelector
    request_requirement: RequestLimitRequirement | None
    connection_requirement: ConnectionLimitRequirement | None
```

The route selector reuses followup-07 declared-location and sample-URI
semantics. A server-wide profile can target the `server` scope directly.

## Nginx Scope and Inheritance Semantics

### Zone Collection

- Collect zone definitions only from legal `http` context after include
  expansion.
- Preserve lexical source but compare definitions globally within one `http`.
- A definition in `server`, `location`, or `if` is illegal and cannot satisfy
  a usage.
- Unknown size units, malformed rates, missing names, or duplicate
  incompatible definitions make dependent assessments `indeterminate`.

### Effective `limit_req` and `limit_conn`

For each directive family independently:

1. Starting at the route scope, find the nearest legal scope containing one
   or more directives of that family.
2. Use the entire ordered list from that scope.
3. If none exists locally, inherit the parent's entire list.
4. Do not merge by zone name.
5. Keep multiple active directives; all are evidence and all enforce.
6. A local single-zone limit replaces a parent multi-zone set and can remove
   a required global limiter.

### Scalar Companion Directives

Resolve `*_dry_run`, `*_status`, and `*_log_level` independently using the
nearest valid value, then documented defaults:

| Directive | Default |
| --- | --- |
| `limit_req_dry_run` | `off` |
| `limit_conn_dry_run` | `off` |
| `limit_req_status` | `503` |
| `limit_conn_status` | `503` |
| `limit_req_log_level` | `error` |
| `limit_conn_log_level` | `error` |

These scalar values are not reset merely because a child replaces the active
limit list.

### `if in location`

Rate-limit module directives are not credited from `if in location`.
Parser-tolerated instances are recorded as illegal-context evidence. They
must not cause a parent or child route to pass.

### Location and Route Selection

Profiles can bind to:

- a server;
- an exact declared location;
- one or more concrete sample URIs resolved by followup-07 semantics.

Named or `internal` locations are assessed only when explicitly targeted.
They are not treated as ordinary public routes. Rewrites and internal
redirects remain outside version 1 and produce `indeterminate` when policy
requires route-complete proof.

### Includes and Completeness

Includes participate in lexical order and retain source spans. A missing,
cyclic, or malformed include affecting a zone definition or route ancestry
makes the dependent assessment `indeterminate`. Complete sibling servers or
unrelated zones remain assessable.

## Policy Schema Fragment

```yaml
schema_version: 1
nginx:
  rate_limits:
    zone_inventory:
      request:
        api_per_ip:
          allowed_keys: ["$binary_remote_addr"]
          min_size: 10m
          rate:
            min: 1r/s
            max: 20r/s
      connection:
        api_conn_per_ip:
          allowed_keys: ["$binary_remote_addr"]
          min_size: 10m
    profiles:
      public_api:
        applies_to:
          server_names: ["api.example.test"]
          declared_locations:
            - modifier: prefix
              pattern: /v1/
          sample_uris: ["/v1/users", "/v1/orders"]
        request:
          required: true
          accepted_zones: [api_per_ip]
          require_all_zones: false
          burst:
            min: 0
            max: 40
          delay_mode: delayed
          max_delay: 20
          dry_run: false
          allowed_rejection_statuses: [429]
          allowed_log_levels: [notice, warn, error]
        connection:
          required: true
          accepted_zones: [api_conn_per_ip]
          connections:
            min: 1
            max: 20
          dry_run: false
          allowed_rejection_statuses: [429, 503]
          allowed_log_levels: [notice, warn, error]
      health:
        applies_to:
          server_names: ["api.example.test"]
          sample_uris: ["/healthz"]
        request:
          required: false
        connection:
          required: false
    unmatched_routes: indeterminate
    unresolved_internal_redirects: indeterminate
```

Validation requirements:

- Zone and profile IDs are unique.
- Sizes parse into positive byte counts using supported Nginx units.
- Rates parse into positive rational values.
- Minimums do not exceed maximums.
- `allowed_keys` are exact normalized Nginx expressions.
- Accepted zone names reference the declared policy inventory.
- `nodelay` and delayed-only settings cannot be requested simultaneously.
- `max_delay` is not greater than `burst`.
- Status codes are valid integers in an allowed policy range.
- Log levels use documented Nginx values.
- A profile requiring neither request nor connection limits is allowed only
  as an explicit exemption profile.
- Overlapping non-equivalent route profiles are rejected.
- Unknown keys are rejected.

Version 1 uses exact key expressions. It does not allow arbitrary regex over
keys or zone names.

## Policy Semantics

### Request Requirement

A request requirement passes when:

1. At least one effective `limit_req` exists if `required` is true.
2. Required or accepted zones are active according to `require_all_zones`.
3. Every zone needed for the decision has a valid definition.
4. The zone key and configured rate satisfy the zone inventory.
5. Usage `burst`, `delay`, and `nodelay` satisfy the route profile.
6. Effective dry-run matches policy.
7. Effective rejection status and log level are allowed.

If multiple active request limits apply, the policy can:

- require a named subset and ignore additional stricter zones;
- reject unapproved additional zones;
- require every effective zone to be inventoried.

The schema should expose this as a bounded `additional_zones` mode:
`allow`, `require_in_inventory`, or `forbid`.

### Connection Requirement

A connection requirement uses analogous logic for:

- active zones;
- zone key and size;
- numeric connection cap;
- dry-run;
- rejection status;
- log level;
- additional-zone policy.

A server-name keyed global connection cap does not satisfy a per-IP CIS
requirement, though it can be allowed as an additional defense.

### Too Strict Versus Too Weak

Both lower and upper bounds are policy decisions:

- A value above maximum can be too weak.
- A value below minimum can be operationally too strict.

Both are assessment failures, but neither automatically creates a security
finding. Evidence and summary must identify which boundary failed.

## Assessment Algorithm

For each matched profile and selected route:

1. Resolve the route scope.
2. Resolve effective request and connection limits plus scalar companions.
3. Resolve referenced zone definitions.
4. Validate evidence completeness and supported syntax.
5. Evaluate request and connection requirements independently.
6. Emit separate assessments for CIS 5.2.4 and 5.2.5 when those controls are
   in policy scope.
7. Optionally emit one aggregate organization policy assessment.
8. Preserve every active zone and source in evidence.

Recommended control IDs:

- `cis-nginx-5.2.4.connections-per-ip`
- `cis-nginx-5.2.5.requests-per-ip`
- `asvs-5.0.0-v2.4.1.anti-automation`
- `policy.nginx.rate-limit.<profile_id>`

A route can pass request-rate policy and fail connection policy. Aggregate
reporting must not hide that distinction.

## Findings Versus Control Assessments

- Existing missing, malformed, unknown-zone, and non-per-IP findings remain
  default-on.
- Policy-specific numeric mismatch is a control assessment, not a new finding
  in version 1.
- Existing findings can be linked via `related_rule_ids`.
- `nginx.limit_req_zone_rate_review` and
  `nginx.limit_conn_zone_review` remain available under
  `--enable-policy-review` when no explicit rate policy applies.
- When an explicit profile assesses a zone and route, the corresponding
  generic review finding should be suppressed for that subject.
- A policy pass never suppresses an invalid-config finding.
- Assessment status does not carry severity.

## Default Behavior Without Policy

With no `nginx.rate_limits` section:

- no rate-limit control assessments are emitted;
- all existing findings, fixed autoindex heuristic, opt-in review findings,
  IDs, ordering, and text remain stable;
- no default numeric values or route profiles are assumed;
- CIS 5.2.4 and 5.2.5 remain `partial`;
- shared resolver refactoring is allowed only after no-policy golden parity
  tests pass.

## Error and Indeterminate Handling

| Condition | Result |
| --- | --- |
| Invalid policy | Followup-03 `AnalysisIssue`; no rate-limit assessments. |
| Root config parse failure | Existing fatal behavior; no assessments. |
| Include error affects a zone or route | Dependent assessment `indeterminate`. |
| Referenced zone missing | Existing finding plus `indeterminate` assessment because Nginx may reject config. |
| Zone definition malformed or duplicated incompatibly | Existing finding where applicable plus `indeterminate`. |
| Complete route has no required limit | `fail`. |
| Effective dry-run is on while policy requires enforcement | `fail`. |
| Key is dynamic and not an exact approved expression | `indeterminate` or `fail` according to explicit `unknown_key` policy; default `indeterminate`. |
| Key can be empty at runtime | Record limitation; `indeterminate` if policy requires non-empty proof. |
| Route selection depends on unresolved rewrite/internal redirect | Follow policy, default `indeterminate`. |
| Directive appears only in illegal `if` context | Ignore for effective semantics; complete route can `fail`. |
| HTTP/2 or HTTP/3 changes connection-count interpretation | Preserve protocol note; compare configured number but do not claim equivalent TCP connection semantics. |
| External/CDN limiter is declared but not represented in Nginx | Outside this local assessment; do not pass on assertion alone. |

## Likely Files

- `src/webconf_audit/local/nginx/effective_scope.py` - reuse followup-05.
- `src/webconf_audit/local/nginx/location_matcher.py` - reuse followup-07.
- `src/webconf_audit/local/nginx/rate_limit_semantics.py` - new zone and
  effective usage model.
- `src/webconf_audit/local/nginx/assessments/rate_limits.py` - new policy
  evaluator.
- `src/webconf_audit/policy/models.py` - add zone inventory and profile
  schema.
- Existing limit rules may consume shared parsing after parity tests:
  - `_limit_utils.py`
  - `missing_limit_req.py`
  - `missing_limit_conn.py`
  - `missing_limit_req_zone.py`
  - `missing_limit_conn_zone.py`
  - `limit_req_unknown_zone.py`
  - `limit_req_zone_invalid_rate.py`
  - `limit_conn_invalid_limit.py`
  - `limit_req_zone_not_per_ip.py`
  - `limit_conn_zone_not_per_ip.py`
  - `limit_req_zone_rate_review.py`
  - `limit_conn_zone_review.py`
- `tests/test_nginx_rate_limit_semantics.py`
- `tests/test_nginx_rate_limit_policy.py`
- `tests/fixtures/webserver-configs/nginx/policy/rate_limits/`

## Comprehensive Test Design

### Zone Parsing

- `limit_req_zone` and `limit_conn_zone` in `http`.
- Zones loaded from includes and nested glob includes.
- Integer `r/s` and `r/m` normalization, including exact equivalence of
  `60r/m` and `1r/s`.
- Supported size units and invalid size.
- `$binary_remote_addr`, `$remote_addr`, user/API-key variables, composite
  keys, and literal keys.
- Empty or malformed key.
- `sync` option preservation.
- Duplicate identical and incompatible zone definitions.
- Zone directive in `server`, `location`, and `if` is not credited.

### Effective List Inheritance

- `http` request and connection lists inherited by server and location.
- Server local list replaces the entire `http` list.
- Location local list replaces the entire server list.
- Multiple same-level request and connection directives remain active.
- A local one-zone list removes a required inherited second zone and fails.
- Request and connection families inherit independently.
- Includes at every legal scope preserve source.
- `if in location` directives do not affect parent or child results.

### Request Options

- No burst, `burst=N`, `nodelay`, and `delay=N`.
- Delay and nodelay contradiction.
- Burst and delay numeric boundaries.
- Missing/duplicate `zone=` option.
- Additional usage options are preserved and unsupported ones become
  indeterminate.
- Very low and very high values exercise min/max policy.

### Scalar Companions

- Defaults for both dry-run directives.
- Inherited and locally overridden dry-run.
- Default and explicit 429/503 status.
- Valid and invalid status values.
- Every request and connection log level.
- Scalar values remain inherited when a child replaces the active limit list.

### Route Profiles

- Server-wide profile.
- Exact, prefix, `^~`, regex, and sample-URI location profiles through
  followup-07 matcher.
- Public API, login, upload, health, static, and internal/named route
  examples.
- A protected health route does not satisfy an unprotected API route.
- An explicit exemption applies only to its matched route.
- Overlapping non-equivalent profiles fail policy validation.
- Rewrite/internal redirect boundary produces indeterminate.

### Assessments

- Request pass and connection fail are separate.
- Wrong key, wrong zone, rate too high, rate too low, burst too high, wrong
  delay mode, dry-run on, wrong status, and disallowed log level.
- Additional zone modes `allow`, `require_in_inventory`, and `forbid`.
- Missing zone produces existing finding plus indeterminate assessment.
- Complete absence of required limit produces fail.
- Evidence includes usage and zone-definition source locations.
- Deterministic ordering and serialization.

### Findings and False-Positive Boundaries

- No-policy golden output matches current analyzer.
- A server-name keyed global zone is not mistaken for a per-IP CIS limit.
- A comment or variable containing `limit_req` is ignored.
- A location named `@fallback` is not treated as public without explicit
  targeting.
- `internal` route limits do not satisfy public route requirements.
- `$http_x_forwarded_for` is not assumed trustworthy client identity.
- Configured limits are not claimed to prove real capacity or distributed
  abuse resistance.
- Generic review findings are suppressed only for explicitly assessed
  subjects.

## Documentation and Coverage Effects

When implementation lands:

- `docs/rule-coverage.md` should distinguish policy assessments from finding
  rules and add partial ASVS/API mappings where justified.
- `docs/control-source-coverage-tracker.md` should retain CIS 5.2.4/5.2.5 as
  `partial` unless the project formally counts explicit workload policy as the
  complete static boundary.
- `docs/benchmarks-covering.md` should explain that values require workload
  profiles.
- `docs/architecture.md` should document zone linking, exact rational rates,
  and route-scoped inheritance.
- CLI/API docs should include a small zone inventory/profile example and
  no-policy behavior.

The full-coverage numerator does not change in this followup.

## Acceptance Criteria

- Policy can express route-specific request and connection limits with
  bounded numeric ranges.
- Zone definitions and usages are linked with source-aware evidence.
- Replacement inheritance is exact for both limit families.
- Multiple active limits, dry-run, status, log level, burst, delay, and
  nodelay are tested.
- Includes and route scopes are comprehensive.
- `if in location` cannot create a false pass.
- Unsupported/dynamic evidence is indeterminate.
- Existing findings and no-policy output remain stable.
- Policy failures are assessments, not duplicate findings.
- Exact CIS, ASVS, and OWASP rows are used with conservative partial notes.
- No runtime capacity or external-limiter claim is made.

## Dependencies

- Followup-03 policy schema and loader.
- Followup-04 assessment output.
- Followup-05 scope graph.
- Followup-07 bounded route matcher.
- Official Nginx request-limit and connection-limit documentation.
- Existing parser/include/source-span behavior.

## Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Numeric defaults become accidental product policy | Require explicit profiles; no universal defaults. |
| Floating-point rate comparisons drift | Normalize to rational values. |
| Any location-level limiter suppresses a server gap | Assess exact route scopes. |
| Local list replacement is mistaken for merge | Resolve whole directive lists at nearest level. |
| Dry-run is mistaken for enforcement | Model it as a required scalar. |
| Client IP key is trusted without proxy-chain evidence | State limitation and allow policy to require a specific key only. |
| Too many route profiles make PR unreviewable | Reuse followup-07 selectors and keep version 1 schema bounded. |
| Old finding behavior changes during parser reuse | Gate helper migration on no-policy golden tests. |

## Rollback Plan

1. Stop registering the rate-limit assessment evaluator.
2. Remove `nginx.rate_limits` from the policy schema.
3. Retain shared scope and route matching from earlier followups.
4. Retain any improved numeric parser only if existing rule parity is proven;
   otherwise restore the previous helper.
5. Keep all current findings and opt-in review rules.
6. Revert only docs describing policy-backed rate limits and keep coverage
   statuses unchanged.

Assessments are derived output and require no data migration.

## Reviewer Checklist

- [ ] Followup-03/04 and route foundations are reused.
- [ ] Zone definitions are legal-context, source-aware, and strictly parsed.
- [ ] Request and connection list inheritance is exact.
- [ ] Multiple active zones are preserved.
- [ ] Rates use rational comparison.
- [ ] Burst, delay, nodelay, dry-run, status, and log levels are explicit.
- [ ] `http`, `server`, `location`, includes, named/internal routes, and `if`
      boundaries are tested.
- [ ] Dynamic keys and incomplete includes do not create guessed passes.
- [ ] Findings and assessments remain separate.
- [ ] No-policy behavior has golden regression tests.
- [ ] Standards rows and partial coverage notes are exact.
- [ ] The pull request remains focused on rate-limit policy and the minimal
      shared semantics required for it.
