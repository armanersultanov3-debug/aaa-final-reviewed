# Nginx Sensitive-Location Policy Design

Date: 2026-06-12
Status: proposed
Sequence: follow-up 07 of 14

## Status and Dependencies

This is the design for followup-07. It replaces the hard-coded notion of a
"sensitive location" with an operator-supplied catalog and exact, source-aware
access-control evidence.

The implementation depends on:

- followup-03 for `AuditPolicy` loading, schema versioning, and strict
  validation;
- followup-04 for `ControlAssessment`;
- followup-05 for the Nginx effective-scope graph and completeness tracking;
- followup-06 only for optional shared selector/profile conventions, not for
  logging behavior;
- PR #9 for conservative coverage classification and the finding versus
  policy-review distinction.

The policy and assessment foundations are consumed rather than duplicated.

## Decision Summary

Add an optional `nginx.sensitive_locations` policy containing a catalog of
business-sensitive routes or declared Nginx locations and the access-control
contract required for each entry. Resolve Nginx location selection for
concrete sample URIs, resolve inherited access and authentication directives,
compose them using effective `satisfy all|any`, and emit one or more
`ControlAssessment` records per catalog entry.

Version 1 supports a bounded set of statically visible controls:

- `internal`;
- ordered `allow`/`deny` address rules;
- `auth_basic` plus effective `auth_basic_user_file`;
- `auth_request`;
- visible `auth_jwt`, `auth_oidc`, or explicitly configured equivalent
  directives when supported by the parser;
- unconditional `return 403`, `return 404`, or `return 444`;
- method-specific `limit_except` evidence when a policy explicitly requests
  it.

The analyzer verifies configuration intent. It does not prove identity
provider behavior, password strength, JWT validation at runtime, network
topology, or application authorization.

## Current Evidence and Rules

The current repository contains useful baseline findings:

- `nginx.missing_access_restrictions_on_sensitive_locations` recognizes only
  `/admin`, `/admin/`, `/phpmyadmin`, `/manage`, and `/internal`.
- That rule deliberately uses a simplified ancestor-chain model and can treat
  a parent `auth_basic` as active even when a child says `auth_basic off`.
- `nginx.sensitive_location_missing_ip_filter` uses the same hard-coded path
  set and a closer approximation for `allow`/`deny`, `auth_basic`, and
  `satisfy`.
- `nginx.allow_all_with_deny_all` catches one local contradictory pattern.
- `nginx.missing_auth_basic_user_file` checks basic-auth configuration.
- `nginx.auth_basic_over_http` checks transport posture where basic auth is
  enabled.
- `nginx.sensitive_config_files_not_restricted` checks a built-in extension
  catalog and maps partial evidence to ASVS V13.4.7.
- `nginx.missing_hidden_files_deny`,
  `nginx.missing_backup_file_deny`, and
  `nginx.missing_generated_artifact_deny` cover other server-wide artifact
  baselines.
- Public status, documentation, autoindex, and similar exposure findings
  provide adjacent evidence but do not know the operator's sensitive route
  inventory.

The coverage tracker marks CIS NGINX section 5.1.1 as `partial` because a
complete sensitive path catalog is business-specific.

## Exact Control Rows

| Source | Row | Exact row text | Intended evidence |
| --- | --- | --- | --- |
| CIS NGINX Benchmark v3.0.0 | 5.1.1 | Ensure allow and deny filters limit access to specific IP addresses | Effective ordered IP filters on policy-declared sensitive routes. |
| OWASP ASVS 5.0.0 | V8.2.1, L1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | Related configuration evidence only; Nginx route controls cannot prove application permissions. |
| OWASP ASVS 5.0.0 | V8.2.4, L3 | Verify that adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session. | IP-address controls are partial evidence when required by policy. |
| OWASP ASVS 5.0.0 | V8.3.1, L1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | Nginx enforcement is trusted-tier related evidence, not full application authorization proof. |
| OWASP ASVS 5.0.0 | V13.4.5, L2 | Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | Direct policy evidence for cataloged documentation and monitoring routes. |
| OWASP ASVS 5.0.0 | V13.4.7, L3 | Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage. | Adjacent artifact policy only; route access policy does not replace extension allowlisting. |
| OWASP Top 10:2021 | A01:2021 | Broken Access Control | Primary category for missing or bypassable route restrictions. |
| OWASP Top 10:2025 | A01:2025 | Broken Access Control | Current-edition companion mapping. |
| OWASP Top 10:2021 | A05:2021 | Security Misconfiguration | Secondary category for unintended route exposure. |
| OWASP Top 10:2025 | A02:2025 | Security Misconfiguration | Current-edition companion mapping for misconfiguration evidence. |
| OWASP Cheat Sheet Series | Access Control Cheat Sheet | Access Control Cheat Sheet | Primary companion guidance. |
| OWASP Cheat Sheet Series | Authentication Cheat Sheet | Authentication Cheat Sheet | Related guidance for authentication-backed controls. |

All ASVS V8 mappings from this feature are `partial` because static Nginx
configuration cannot prove application authorization decisions. ASVS
V13.4.5 can receive direct configuration evidence for a specifically
cataloged documentation or monitoring route, while runtime exposure remains a
separate corroboration layer.

## Official Nginx Rules to Model

### Location Selection

- Exact locations (`location = /path`) terminate the search on exact match.
- Prefix locations are considered by longest matching prefix.
- Regular-expression locations are checked in declaration order after the
  longest prefix is remembered.
- A longest prefix marked `^~` suppresses the regular-expression search.
- The first matching regex location wins.
- Named locations (`location @name`) are not selected by ordinary external
  URI processing.
- Locations can be nested within documented constraints.
- Request matching uses a normalized URI after percent-decoding, resolution
  of `.` and `..`, and optional slash compression.

### Address Access Rules

- `allow` and `deny` are valid in `http`, `server`, `location`, and
  `limit_except`.
- Rules are checked in declaration order until the first match.
- The nearest level containing any `allow` or `deny` directives replaces the
  inherited list as a unit.
- `allow all` or an early broad allow can make a later `deny all`
  ineffective.

### Authentication and Composition

- `auth_basic off` cancels inherited basic authentication.
- Effective `auth_basic_user_file` must be resolved separately.
- `satisfy all` is the default.
- `satisfy all` requires every configured access/authentication module to
  allow access.
- `satisfy any` allows access when any configured module allows it.
- `auth_request off` and equivalent module-specific off values cancel
  inherited controls where documented.
- `internal` allows only internal requests and returns 404 for ordinary
  external requests.

An unconditional `return` in a location is distinct from a conditional
`return` nested in `if`. The latter must not be treated as a route-wide deny.

## Gaps to Close

1. The sensitive route catalog is hard-coded and cannot represent an
   organization's actual admin, support, metrics, documentation, or internal
   API paths.
2. Current matching checks location arguments textually instead of resolving
   location precedence for concrete URIs.
3. Parent controls can be incorrectly credited after child cancellation or
   replacement.
4. `allow`/`deny` order is security-significant but not fully modeled.
5. `satisfy any` can turn a strong-looking combination into a bypass and must
   be evaluated against the policy's intended composition.
6. Authentication modules beyond basic auth are not represented in a common
   access-control model.
7. `internal`, named locations, and unconditional deny responses need clear
   exposure semantics.
8. A `limit_except` control protects methods, not necessarily the entire
   route.
9. Regex route coverage and shadowing can produce false confidence.
10. Includes and partial parse trees can hide stronger or weaker location
    definitions.
11. Existing findings need to remain useful without duplicating policy
    failures.

## Goals

- Accept an explicit sensitive route/location catalog.
- Resolve effective Nginx access controls and their composition.
- Resolve concrete URI samples using documented location precedence.
- Detect child cancellation, list replacement, broad early allows, and
  `satisfy any` bypasses.
- Distinguish externally denied, internally reachable, authenticated,
  IP-restricted, and unprotected routes.
- Preserve source and inheritance evidence across includes.
- Emit deterministic control assessments without changing default findings.
- Keep business-policy and runtime boundaries explicit.

## Non-Goals

- Do not crawl the application or discover every sensitive endpoint.
- Do not prove application-level authorization, role membership, or object
  access.
- Do not contact an identity provider, auth subrequest endpoint, or JWT key
  source.
- Do not parse password files or validate credential strength.
- Do not prove network source addresses, VPN topology, or CDN behavior.
- Do not solve arbitrary regex language inclusion or prove that one regex
  covers all strings in another.
- Do not execute rewrite, `try_files`, error-page, or internal-redirect flows
  in version 1.
- Do not count an `if` branch as unconditional route protection.
- Do not replace the separate sensitive-file extension policy.
- Do not promote CIS 5.1.1 to full coverage merely because a policy catalog is
  present.

## Foundation Contract

The evaluator consumes:

```text
AuditPolicy
  schema_version
  nginx.sensitive_locations | null
```

Each emitted assessment must include:

- `policy_section: "nginx.sensitive_locations"`
- `catalog_entry_id`
- `server_scope_id`
- declared location scope and/or resolved URI sample;
- effective access-control modules;
- effective `satisfy` mode;
- ordered access rules;
- protection classification;
- evidence sources and completeness.

Assessment output belongs in `AnalysisResult.control_assessments`. Catalog
entries and route manifests are policy input, not findings.

## Proposed Models

### Sensitive Catalog Entry

```python
class SensitiveLocationEntry:
    entry_id: str
    kind: Literal[
        "admin", "documentation", "monitoring", "internal_api",
        "support", "custom"
    ]
    server_names: tuple[str, ...]
    declared_location: LocationSelector | None
    sample_uris: tuple[str, ...]
    exposure: Literal["external", "internal_only", "disabled"]
    required_controls: AccessControlRequirement
```

An entry must provide a `declared_location`, one or more concrete
`sample_uris`, or both. Providing both is recommended because it detects
shadowing between the intended block and the block selected for a sample URI.

### Location Selector

```python
class LocationSelector:
    modifier: Literal["exact", "prefix", "prefix_no_regex", "regex", "regex_i", "named"]
    pattern: str
    source_path: str | None
```

This selector matches a declared Nginx location exactly after normalization.
It is not a second runtime routing language.

### Ordered Address Rule

```python
class AddressAccessRule:
    action: Literal["allow", "deny"]
    subject_kind: Literal["all", "ip", "cidr", "unix", "hostname", "dynamic"]
    subject: str
    source: SourceSpan
```

Hostnames and dynamic values are retained as evidence but are
`indeterminate` for exact CIDR inventory checks unless policy allows them.

### Effective Access Control

```python
class EffectiveAccessControl:
    scope_id: str
    internal_only: bool
    unconditional_return: int | None
    address_rules: tuple[AddressAccessRule, ...]
    auth_basic: AuthControlState
    auth_request: AuthControlState
    auth_jwt: AuthControlState
    auth_oidc: AuthControlState
    satisfy: Literal["all", "any"]
    method_overrides: tuple[MethodAccessControl, ...]
    complete: bool
    indeterminate_reasons: tuple[str, ...]
```

`AuthControlState` records `enabled`, `off`, `absent`, or `unknown`, source,
origin, and required companion configuration such as a user file or auth URI.

### Protection Classification

```python
class ProtectionClassification(str, Enum):
    UNCONDITIONALLY_DENIED = "unconditionally_denied"
    INTERNAL_ONLY = "internal_only"
    IP_RESTRICTED = "ip_restricted"
    AUTHENTICATED = "authenticated"
    IP_AND_AUTH = "ip_and_auth"
    IP_OR_AUTH = "ip_or_auth"
    METHOD_RESTRICTED_ONLY = "method_restricted_only"
    UNPROTECTED = "unprotected"
    INDETERMINATE = "indeterminate"
```

The classification is descriptive evidence. Policy requirements decide
whether it passes.

## Nginx Scope, Inheritance, and Routing Semantics

### Declared Location Resolution

The evaluator can bind directly to a declared location using exact modifier
and pattern equality. It must retain duplicate matching declarations as an
ambiguity rather than selecting one silently.

### Concrete URI Resolution

For each sample URI and server:

1. Normalize the URI using the documented static transformations that do not
   require runtime variables.
2. Select exact locations first.
3. Select the longest prefix.
4. If that prefix uses `^~`, select it.
5. Otherwise evaluate regex locations in source order and select the first
   matching regex.
6. Fall back to the remembered prefix.
7. Apply nested location selection where supported by the current Nginx
   grammar.

Invalid or dynamically constructed regex evidence makes the sample
`indeterminate`. Named locations are never selected for an external sample
URI.

The evaluator does not follow rewrites or internal redirects. If the selected
scope contains a rewrite that can move processing elsewhere, record that
boundary and apply policy:

- `allow_unresolved_internal_redirects: false` -> `indeterminate`;
- `true` -> assess the selected scope but retain a limitation note.

### Address Rule Inheritance and Evaluation

- Use the nearest scope containing any `allow` or `deny`.
- Preserve declaration order.
- Classify a route as a closed allowlist only when the ordered rules establish
  policy-approved allows followed by an effective deny fallback.
- `allow all` before `deny all` is not restrictive.
- `deny all` first is unconditional for address access, though `satisfy any`
  may still allow an authentication module to grant access.
- A hostname is not converted to an IP during static analysis.

### Authentication Inheritance

Each auth directive family resolves independently according to its documented
inheritance:

- `auth_basic off` explicitly disables inherited basic auth.
- Enabled basic auth without an effective user file is incomplete and cannot
  satisfy an authentication requirement.
- `auth_request off` disables inherited auth request.
- Commercial or optional module directives are recognized only when their
  static syntax is supported. Presence does not prove module availability or
  successful verification.

### `satisfy`

Resolve the nearest effective `satisfy`, defaulting to `all`.

- With `all`, every enabled access/auth module must grant access.
- With `any`, one permissive module can bypass another.
- A policy requiring both IP and authentication fails on effective
  `satisfy any`.
- A policy intentionally allowing either can require `any`.
- A deny-only address module combined with enabled auth under `any` is
  classified as authentication-only for external callers, not IP-restricted.

### `internal`, `return`, `if`, and `limit_except`

- `internal` satisfies an `internal_only` exposure contract for ordinary
  external requests.
- It does not prove authorization for internal subrequests.
- An unconditional location-level `return 403|404|444` satisfies a disabled
  route contract.
- A `return` inside `if` is conditional and cannot satisfy route-wide denial.
- `allow`, `deny`, `auth_basic`, and `satisfy` inside unsupported `if`
  contexts do not change the parent effective result.
- `limit_except` protects only methods outside its allowlist. It is assessed
  separately and cannot satisfy a whole-route requirement unless the policy
  explicitly describes the allowed methods and base-scope controls.

### Includes and Completeness

Included locations and directives participate in lexical order and retain
their source locations. A missing, cyclic, or malformed include affecting a
server makes relevant route selection or access-control evidence
`indeterminate`. A complete sibling server can still be assessed.

## Policy Schema Fragment

```yaml
schema_version: 1
nginx:
  sensitive_locations:
    catalog:
      - id: admin-console
        kind: admin
        server_names: ["app.example.test"]
        declared_location:
          modifier: prefix_no_regex
          pattern: /admin/
        sample_uris:
          - /admin/
          - /admin/users
        exposure: external
        required_controls:
          all_of:
            - ip_allowlist:
                allowed_cidrs: ["10.20.0.0/16", "2001:db8:20::/48"]
                require_deny_all_fallback: true
            - one_of:
                - auth_request: {}
                - auth_jwt: {}
          satisfy: all
      - id: metrics
        kind: monitoring
        server_names: ["app.example.test"]
        sample_uris: ["/metrics"]
        exposure: internal_only
        required_controls:
          one_of:
            - internal: {}
            - deny_all: {}
      - id: openapi
        kind: documentation
        server_names: ["api.example.test"]
        sample_uris: ["/openapi.json", "/docs/"]
        exposure: disabled
        required_controls:
          all_of:
            - deny_all: {}
    unmatched_entries: indeterminate
    allow_unresolved_internal_redirects: false
```

Validation requirements:

- Catalog IDs are unique.
- Server names and sample URIs are non-empty and normalized.
- Sample URIs are absolute paths without scheme or host.
- Location selectors use one documented Nginx modifier.
- Regex selectors compile under the analyzer's regex engine; unsupported PCRE
  constructs are rejected or marked unsupported explicitly.
- `all_of` and `one_of` are finite, non-empty trees with a maximum depth set
  by followup-03, recommended depth two for version 1.
- `satisfy` requirements cannot contradict the requested boolean expression.
- CIDRs parse strictly; hostnames are a separate policy type.
- `exposure: disabled` requires `deny_all` or an equivalent unconditional
  deny, not authentication alone.
- `exposure: internal_only` requires `internal` or unconditional external
  denial.
- Overlapping entries are allowed only when they have identical requirements
  or are explicitly linked as aliases.
- Unknown controls and unknown keys are rejected.

## Assessment Algorithm

For each catalog entry:

1. Select matching servers by effective `server_name`.
2. Resolve the declared location, each sample URI, or both.
3. If both forms are provided and a sample resolves to a different location,
   record shadowing evidence.
4. Resolve effective access controls for every selected scope.
5. Classify ordered address rules, auth states, `satisfy`, `internal`,
   unconditional deny, and method-only controls.
6. Evaluate the entry's boolean requirement.
7. Emit:
   - `pass` when all samples and declared targets satisfy the requirement;
   - `fail` when complete static evidence proves a requirement is not met;
   - `indeterminate` when routing, includes, dynamic values, optional module
     availability, or internal redirects prevent a sound conclusion;
   - `not-applicable` when policy explicitly permits no matching server and
     followup-04 requires an explicit record.
8. Include every divergent sample in assessment evidence.

Recommended control IDs:

- `cis-nginx-5.1.1.sensitive-ip-filters`
- `asvs-5.0.0-v13.4.5.sensitive-endpoint-exposure`
- `policy.nginx.sensitive-location.<entry_id>`

CIS 5.1.1 is evaluated only when the entry requires an IP filter. A route
protected solely by authentication can pass its organization policy while
remaining `not-applicable` or `fail` for the CIS IP-filter assessment,
depending on the benchmark scope declared by policy.

## Findings Versus Control Assessments

- Existing hard-coded findings remain default-on and unchanged without
  policy.
- Catalog mismatch or policy failure is a control assessment, not a duplicate
  finding in version 1.
- Existing findings may be linked through `related_rule_ids`.
- When a policy entry precisely covers one of the hard-coded baseline paths,
  the built-in finding still reports an unconditional baseline defect if its
  rule detects one. The assessment supplies the business-context result.
- A policy pass does not suppress an existing finding unless a later,
  separately reviewed migration explicitly replaces that rule with the
  shared resolver.
- An explicit assessment never suppresses a `policy-review` finding
  automatically. It may link that finding as related evidence; suppression
  remains a separate, explicit user decision.
- Assessment failure has no severity and must not alter finding calibration.

## Default Behavior Without Policy

With no `nginx.sensitive_locations` section:

- no sensitive-location control assessments are emitted;
- the five built-in sensitive paths and all existing findings behave exactly
  as before;
- no new route catalog is assumed from filenames, comments, upstream names,
  or server names;
- no optional auth module is required;
- CIS 5.1.1 stays `partial`.

No-policy parity is a release gate.

## Error and Indeterminate Handling

| Condition | Result |
| --- | --- |
| Policy file invalid | Followup-03 `AnalysisIssue`; no sensitive-location assessments. |
| Root config parse failure | Existing fatal behavior; no assessments. |
| Include error affects route declarations or controls | `indeterminate` for affected entries. |
| Catalog server has no matching server block | Follow `unmatched_entries`; default `indeterminate`. |
| Declared location selector matches multiple blocks | `indeterminate` with all candidates. |
| Sample URI uses unsupported PCRE behavior | `indeterminate`; do not approximate a pass. |
| Rewrite/internal redirect can move processing and policy forbids unresolved redirects | `indeterminate`. |
| Dynamic CIDR/hostname access rule is required for proof | `indeterminate` unless policy explicitly allows that exact dynamic form. |
| Complete evidence shows no required control | `fail`. |
| Basic auth enabled without effective user file | Existing finding plus `indeterminate` authentication control. |
| Optional auth directive present but module availability is unknown | `indeterminate` unless deployment metadata declares the module. |
| Control appears only inside `if` | Do not credit it as unconditional; complete parent evidence can `fail`. |
| Protection exists only in `limit_except` | Whole-route requirement `fail`; method-specific assessment may pass. |

## Likely Files

- `src/webconf_audit/local/nginx/effective_scope.py` - reuse followup-05.
- `src/webconf_audit/local/nginx/location_matcher.py` - new bounded concrete
  URI resolver.
- `src/webconf_audit/local/nginx/access_control_semantics.py` - new effective
  access/auth model.
- `src/webconf_audit/local/nginx/assessments/sensitive_locations.py` - new
  catalog evaluator.
- `src/webconf_audit/policy/models.py` - add catalog and requirement models.
- Existing rules may later consume the shared resolver after parity tests:
  - `missing_access_restrictions_on_sensitive_locations.py`
  - `sensitive_location_missing_ip_filter.py`
  - `missing_auth_basic_user_file.py`
  - `allow_all_with_deny_all.py`
- `tests/test_nginx_location_matcher.py`
- `tests/test_nginx_access_control_semantics.py`
- `tests/test_nginx_sensitive_location_policy.py`
- `tests/fixtures/webserver-configs/nginx/policy/sensitive_locations/`

## Comprehensive Test Design

### Catalog and Policy Validation

- Unique and duplicate entry IDs.
- Exact, prefix, `^~`, case-sensitive regex, case-insensitive regex, and named
  selectors.
- Entry with only a selector, only samples, and both.
- Invalid URI, CIDR, regex, boolean tree, and contradictory exposure.
- Equivalent overlapping aliases and conflicting overlaps.
- Unknown keys and controls.

### Location Matching

- Exact match wins over prefix and regex.
- Longest prefix is remembered.
- `^~` suppresses regex checks.
- First matching regex wins in source order.
- Case-sensitive and case-insensitive regex behavior.
- Nested locations.
- Named location never matches an external sample.
- URI percent-decoding, dot-segment normalization, and slash compression
  within the supported static boundary.
- `merge_slashes off` is represented and tested.
- Unsupported PCRE construct produces indeterminate, not fallback matching.
- Included regex locations retain lexical order across files.
- A policy-declared block shadowed by a regex sample is detected.

### Access Rule Semantics

- Parent allowlist inherited by child with no local rules.
- One child `allow` or `deny` list replaces the whole parent list.
- `allow trusted; deny all;` passes.
- `allow all; deny all;` does not pass.
- `deny all; allow trusted;` is unconditional address denial because first
  match wins.
- IPv4, IPv6, CIDR, `unix:`, `all`, hostname, and dynamic values.
- Similar CIDRs do not pass exact inventory checks.
- Rule order is preserved through includes.

### Authentication and `satisfy`

- Enabled inherited basic auth.
- Child `auth_basic off` cancels parent.
- Effective inherited and local `auth_basic_user_file`.
- Enabled basic auth without user file is incomplete.
- `auth_request` enabled and disabled.
- Visible `auth_jwt`/`auth_oidc` enabled, off, and unknown module support.
- Default `satisfy all`.
- Explicit `satisfy all` requires both IP and auth.
- `satisfy any` satisfies an intentional OR policy.
- `satisfy any` fails a required IP-and-auth policy.
- Deny-all plus authentication under `any` is not misclassified as IP
  allowlisting.

### `internal`, `return`, `if`, and Methods

- `internal` passes an internal-only contract and not a public authenticated
  contract.
- Unconditional `return 403`, `404`, and `444`.
- Redirect `return 301` does not count as denial.
- `return 403` inside `if` is not route-wide protection.
- Parser-accepted `allow`, `deny`, or auth directives in `if` do not leak into
  parent semantics.
- `limit_except GET` protects non-GET methods only.
- Method-specific requirement passes while whole-route requirement fails.

### Includes and Completeness

- Sensitive location declared in an include.
- Access rules and auth companions declared in separate includes.
- Nested/glob includes preserve source and order.
- Missing include under one server makes only that entry indeterminate.
- Include cycle and malformed include preserve issue codes.
- Complete sibling server remains assessable.

### Findings, Assessments, and False Positives

- No-policy golden findings match current behavior.
- `/administrator` does not match a catalog entry for exact `/admin`.
- A static assets regex containing the word `admin` is not sensitive unless
  cataloged.
- A named internal fallback is not treated as externally reachable.
- Authentication presence is not claimed to prove authorization.
- An IP filter is not claimed effective for clients behind an unmodeled
  trusted proxy chain.
- Separate catalog entries produce separate evidence and deterministic order.
- Policy failure does not create a duplicate finding.

## Documentation and Coverage Effects

When implementation lands:

- `docs/rule-coverage.md` should document the policy assessment capability and
  retain partial notes for ASVS authorization mappings.
- `docs/control-source-coverage-tracker.md` should keep CIS 5.1.1 `partial`
  unless the project formally defines a policy-required catalog as the full
  static boundary.
- ASVS V13.4.5 may gain stronger route-specific evidence, but runtime
  exposure and application intent remain separate.
- ASVS V13.4.7 remains owned by the sensitive-file extension family.
- `docs/benchmarks-covering.md` should explain the operator catalog
  requirement.
- `docs/architecture.md` should document the bounded location matcher and
  effective access-control model.
- CLI/API docs should include one catalog example and the no-policy behavior.

No default coverage numerator change is part of this followup.

## Acceptance Criteria

- An operator can declare sensitive routes and required controls without code
  changes.
- Location matching for concrete samples follows documented Nginx precedence.
- Effective access rules honor nearest-list replacement and declaration
  order.
- `auth_basic off`, companion user files, `satisfy all|any`, `internal`,
  unconditional returns, `if`, and `limit_except` are tested.
- Includes preserve source evidence and incompleteness.
- Unsupported routing or auth evidence becomes `indeterminate`.
- Existing findings and no-policy output remain stable.
- Policy failures are assessments, not duplicate findings.
- Exact standards rows and partial-evidence notes are used.
- Coverage remains conservative.

## Dependencies

- Followup-03 policy model and loader.
- Followup-04 assessment model and output integration.
- Followup-05 scope graph and include completeness.
- Official Nginx core, access, basic-auth, auth-request, and optional auth
  module documentation.
- The existing Nginx parser's token and source fidelity.

## Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| A custom route DSL diverges from Nginx | Use exact declared-location selectors plus concrete sample URIs. |
| Regex overlap creates false confidence | Do not solve language inclusion; return indeterminate for unsupported cases. |
| Authentication is mistaken for authorization | Mark ASVS V8 evidence partial and state runtime/application boundary. |
| `satisfy any` bypass is overlooked | Model module composition explicitly and test it as a first-class outcome. |
| Parent controls survive child cancellation incorrectly | Resolve each directive family with documented nearest-level semantics. |
| `if` creates false route-wide protection | Treat `if` as a conditional branch only. |
| Catalog omissions are interpreted as secure | Assess only declared entries and keep unmatched policy explicit. |
| Existing baseline findings regress | Require no-policy golden tests before shared-helper migration. |

## Rollback Plan

1. Stop registering the sensitive-location assessment evaluator.
2. Remove `nginx.sensitive_locations` from the policy schema.
3. Retain the followup-05 scope graph.
4. Retain the location matcher only if later route-manifest work depends on
   it; otherwise remove it and its tests.
5. Preserve all existing hard-coded sensitive-location and artifact findings.
6. Revert only policy capability documentation and retain conservative
   coverage status.

No persistent migration is needed because assessments are derived.

## Reviewer Checklist

- [ ] Followup-03/04 models are reused.
- [ ] Catalog entries and selector semantics are bounded and validated.
- [ ] Exact/prefix/`^~`/regex/named location behavior is tested.
- [ ] Includes preserve regex order and source locations.
- [ ] `allow`/`deny` order and nearest-level replacement are exact.
- [ ] `auth_basic off` and required companion configuration are handled.
- [ ] `satisfy any` cannot accidentally pass an AND requirement.
- [ ] `internal`, unconditional return, `if`, and `limit_except` boundaries are
      explicit.
- [ ] Runtime identity-provider and application authorization claims are not
      made.
- [ ] Findings and assessments remain distinct.
- [ ] No-policy output has golden regression coverage.
- [ ] Exact CIS/ASVS/OWASP rows and conservative coverage notes are present.
- [ ] The pull request remains limited to sensitive-route policy and the
      minimal location/access semantics needed for it.
