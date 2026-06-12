# Nginx Reverse-Proxy Header Semantics Design

Date: 2026-06-12
Status: proposed
Sequence: follow-up 05 of 14

## Status and Dependencies

This is the design for followup-05. It turns the narrower reverse-proxy
signals recognized in PR #9 into policy-backed control evidence without
changing the default finding set.

The implementation consumes, and does not redefine, the foundations planned
by followup-03 and followup-04:

- `AuditPolicy` is the versioned, strictly validated policy document loaded by
  followup-03.
- `ControlAssessment` is the structured control-assessment result introduced by
  followup-04.
- The shared assessment statuses used by this evaluator are `pass`, `fail`,
  `not-applicable`, and `indeterminate`.
- An absent policy section produces no assessment for that section.
- A policy load error is an `AnalysisIssue`; it must not be converted into a
  security finding.

If followup-03 or followup-04 chooses different module or field names, the
implementation may adapt names but must preserve the behavioral contract in
this document.

This design also introduces the first reusable Nginx effective-scope graph for
the later followup-06 through followup-09 work. Domain-specific proxy
semantics remain in a proxy module rather than in the generic graph.

## Decision Summary

Add an optional `nginx.reverse_proxy_headers` policy that evaluates each
supported upstream route against explicit request-header and response-header
requirements. Build a source-aware `http` -> `server` -> `location` scope
graph, resolve module-specific inheritance exactly, and emit
`ControlAssessment` records. Keep existing unconditional findings, including
`nginx.proxy_missing_source_ip_headers` and
`nginx.proxy_set_header_host_spoofing`, unchanged when no policy is supplied.

The initial implementation covers the four upstream families already
recognized by the Nginx analyzer:

| Upstream family | Route directive | Request-header directives | Response filtering directives |
| --- | --- | --- | --- |
| HTTP proxy | `proxy_pass` | `proxy_set_header` | `proxy_hide_header`, `proxy_pass_header` |
| FastCGI | `fastcgi_pass` | `fastcgi_param` | `fastcgi_hide_header`, `fastcgi_pass_header` |
| gRPC | `grpc_pass` | `grpc_set_header` | `grpc_hide_header`, `grpc_pass_header` |
| uwsgi | `uwsgi_pass` | `uwsgi_param` | `uwsgi_hide_header`, `uwsgi_pass_header` |

SCGI and third-party upstream modules are outside the first implementation.
Their presence is reported as unsupported evidence, not silently evaluated as
HTTP proxy configuration.

## Current Evidence and Rules

PR #9 merged as commit `1e1cbbb` and established three constraints relevant
to this work:

1. `policy-review` is an opt-in tag, not a rule category or severity.
2. Evidence strength in standards mapping is distinct from finding severity.
3. Effective Nginx values must retain source file and line information across
   includes and nested scopes.

The current repository has useful but incomplete signals:

- `nginx.proxy_missing_source_ip_headers` checks `proxy_pass`,
  `fastcgi_pass`, `grpc_pass`, and `uwsgi_pass` scopes for selected
  source-IP headers.
- The HTTP proxy branch expects:
  `X-Forwarded-For $proxy_add_x_forwarded_for` or `$remote_addr`,
  `X-Real-IP $remote_addr`, and `X-Forwarded-Proto $scheme`.
- The FastCGI branch checks `X-Forwarded-For` and `X-Real-IP`; the gRPC and
  uwsgi branches check `X-Forwarded-For`.
- `nginx.proxy_set_header_host_spoofing` rejects obviously user-controlled
  `Host` values and accepts `$host` or a fixed value.
- `nginx.proxy_ssl_verify_disabled` and
  `nginx.proxy_ssl_trusted_certificate_missing` cover upstream TLS posture,
  but do not participate in header policy.
- `nginx.proxy_pass_user_controlled_destination` covers dynamic upstream
  destination taint, not header inheritance.
- The current helper logic uses a broad "local directives replace inherited
  directives" approximation and does not expose a stable per-route effective
  model.
- The coverage tracker marks CIS NGINX section 2.5.4 as `partial` because
  complete reverse-proxy response-header semantics are not modeled.
- CIS NGINX section 3.4 is `full` for the current bounded source-IP check, but
  it is not an organization-specific assertion that every route uses the
  operator's chosen trust chain and header names.

The parser expands includes in place and preserves `SourceSpan`, but the AST
does not currently provide parent links, stable scope identifiers, or
completeness markers for partially loaded include trees.

## Exact Control Rows

The implementation and documentation must use these rows verbatim where the
control text is displayed:

| Source | Row | Exact row text | Intended evidence |
| --- | --- | --- | --- |
| CIS NGINX Benchmark v3.0.0 | 2.5.4 | Ensure the NGINX reverse proxy does not enable information disclosure | Effective response-header suppression and explicit exceptions on upstream routes. |
| CIS NGINX Benchmark v3.0.0 | 3.4 | Ensure proxies pass source IP information | Effective source identity and scheme headers on each supported upstream route. |
| OWASP ASVS 5.0.0 | V13.4.5, L2 | Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | Related only when a proxy route exposes an operator-declared internal endpoint. This is not direct credit for generic proxy headers. |
| OWASP ASVS 5.0.0 | V13.4.6, L3 | Verify that the application does not expose detailed version information of backend components. | Effective removal of `Server`, `X-Powered-By`, and policy-declared backend disclosure headers. |
| OWASP ASVS 5.0.0 | V16.2.1, L2 | Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens. | Related evidence only: preserving trusted client identity can support downstream logs. |
| OWASP Top 10:2021 | A05:2021 | Security Misconfiguration | Primary OWASP category for response disclosure and unsafe proxy header configuration. |
| OWASP Top 10:2025 | A02:2025 | Security Misconfiguration | Current-edition companion mapping used by the repository. |
| OWASP Cheat Sheet Series | Logging Cheat Sheet | Logging Cheat Sheet | Related guidance for trusted source identity propagation. |
| OWASP Cheat Sheet Series | HTTP Security Response Headers Cheat Sheet | HTTP Security Response Headers Cheat Sheet | Related guidance for suppressing unnecessary response disclosure. |
| OWASP Cheat Sheet Series | Server Headers Cheat Sheet | Server Headers Cheat Sheet | Direct companion guidance for backend version/header disclosure. |

CIS references use the repository's existing CIS NGINX v3.0.0 source URL.
ASVS text comes from the official OWASP ASVS v5.0.0 CSV. OWASP Top 10 and
Cheat Sheet mappings remain living references and do not become full control
rows in the CIS coverage numerator.

## Gaps to Close

1. A child `proxy_set_header` list replaces the entire inherited
   `proxy_set_header` list when any local directive exists. The analyzer must
   not merge headers by name.
2. Nginx supplies default `Host $proxy_host` and `Connection close` behavior
   when no explicit list replaces it. An empty header value means the header
   is not sent.
3. Header names are case-insensitive, but repeated configured directives and
   their order must be preserved as evidence.
4. Response disclosure depends on the upstream module's built-in hidden
   headers plus effective `*_hide_header` and `*_pass_header` configuration.
5. A safe directive at `http` level can be shadowed by a partial local list in
   a `server` or `location`.
6. A directive inside an `if` block must not be treated as an unconditional
   parent value. `proxy_set_header` is not valid in `if in location`.
7. Includes can contribute directives at any legal context. Evidence must
   point to the included file, not only the root config.
8. Static analysis cannot prove the backend's actual response headers or
   whether a load balancer rewrites them later.
9. Current findings do not distinguish an unconditional defect from failure
   to meet an operator-selected header contract.

## Goals

- Build a reusable, source-aware Nginx scope graph.
- Resolve effective proxy request headers with module-correct replacement
  inheritance and defaults.
- Resolve effective response-header suppression/pass-through behavior for the
  four supported upstream families.
- Evaluate explicit route profiles from `AuditPolicy`.
- Preserve all evidence directives, source locations, inherited-from scope,
  and reasons for the computed value.
- Keep findings and control assessments separate.
- Avoid false positives for non-proxy locations, unsupported modules, safe
  fixed `Host` values, and headers intentionally removed with an empty value.
- Make CIS 2.5.4 and 3.4 policy evidence reproducible without claiming runtime
  proof.

## Non-Goals

- Do not fetch a backend or inspect live response headers.
- Do not infer the trusted proxy chain from network topology.
- Do not validate `real_ip_header`, CDN configuration, service-mesh behavior,
  or load-balancer rewrites in this pull request.
- Do not prove ASVS V13.4.5 for arbitrary application routes.
- Do not add SCGI or third-party module semantics.
- Do not evaluate directives in syntactically invalid contexts as if Nginx
  accepted them.
- Do not replace or weaken existing unconditional proxy findings.
- Do not promote CIS 2.5.4 to full coverage solely because this static policy
  assessment exists.

## Foundation Contract

The evaluator consumes:

```text
AuditPolicy
  schema_version
  nginx.reverse_proxy_headers | null
```

It emits zero or more:

```text
ControlAssessment
  control_id
  title
  status
  scope
  summary
  evidence[]
  related_rule_ids[]
  policy_source
  metadata
```

Minimum metadata required by this design:

- `policy_section: "nginx.reverse_proxy_headers"`
- `server_scope_id`
- `route_scope_id`
- `upstream_family`
- `profile_id`
- `effective_request_headers`
- `effective_response_header_filters`
- `unsupported_or_dynamic_evidence`

The common result model owns serialization. This feature must not place
assessment-shaped data in `Finding.metadata`.

## Proposed Nginx Models

### Generic Scope Graph

Add a reusable immutable view over the expanded AST:

```python
class NginxScopeKind(str, Enum):
    MAIN = "main"
    HTTP = "http"
    SERVER = "server"
    LOCATION = "location"
    IF_IN_LOCATION = "if_in_location"
    LIMIT_EXCEPT = "limit_except"


class NginxScope:
    scope_id: str
    kind: NginxScopeKind
    parent_id: str | None
    block: BlockNode | None
    selector: str | None
    source: SourceSpan
    complete: bool
    completeness_issues: tuple[str, ...]
```

`scope_id` must be deterministic for one expanded configuration and must not
depend on Python object identity. A recommended shape is a hash of normalized
source path, block start line, scope kind, and sibling ordinal.

The graph does not attempt to prove which location wins for an arbitrary URI.
It represents syntactic scopes and inheritance paths only.

### Proxy Route

```python
class ProxyRoute:
    route_id: str
    scope_id: str
    upstream_family: Literal["proxy", "fastcgi", "grpc", "uwsgi"]
    pass_directive: DirectiveNode
    destination_tokens: tuple[str, ...]
    destination_kind: Literal["literal", "variable", "named_upstream"]
```

Every supported `*_pass` directive creates a route at its containing legal
scope. Nested locations are independent routes. A location that inherits
other proxy settings but has no `*_pass` directive is not independently
assessed unless a future route manifest explicitly binds it.

### Effective Header Evidence

```python
class EffectiveHeaderValue:
    normalized_name: str
    configured_name: str
    value_tokens: tuple[str, ...]
    rendered_value: str
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str
    origin: Literal["explicit", "inherited", "nginx_default"]
    disposition: Literal["set", "removed", "hidden", "passed"]
```

Values remain token-based. The evaluator may classify known variables, but it
must not collapse an expression such as `$http_x_forwarded_for, $remote_addr`
into a single opaque truth value.

### Resolution Result

```python
class ProxyHeaderResolution:
    route: ProxyRoute
    request_headers: tuple[EffectiveHeaderValue, ...]
    response_hidden_headers: frozenset[str]
    response_passed_headers: frozenset[str]
    complete: bool
    indeterminate_reasons: tuple[str, ...]
```

## Nginx Scope and Inheritance Semantics

### Legal Contexts

- `proxy_set_header`, `proxy_hide_header`, and `proxy_pass_header` are
  evaluated only in `http`, `server`, and `location`.
- Equivalent FastCGI, gRPC, and uwsgi directives are evaluated only in their
  documented legal contexts.
- `if in location` is represented in the graph for later response-header and
  logging work, but it is not a legal source of `proxy_set_header`.
- A parser-tolerated directive in an illegal context is excluded from
  effective values and recorded as unsupported evidence.

### Request Header Replacement

For each upstream family:

1. Find the nearest ancestor scope, including the route scope, that declares
   at least one family setter directive.
2. Use the complete ordered list from that scope.
3. Do not merge missing names from the parent list.
4. If no explicit list exists, apply only documented Nginx defaults for that
   module.
5. Normalize names case-insensitively for comparison while retaining original
   spelling and duplicates for evidence.
6. An empty configured value has `disposition="removed"` and cannot satisfy a
   required-header assertion.

For HTTP proxy routes, the documented default list includes
`Host $proxy_host` and `Connection close`. Those defaults do not satisfy a
policy that explicitly requires `Host $host`.

### Response Header Filtering

The resolver starts with each upstream module's documented built-in hidden
response headers, then applies effective `*_hide_header` and
`*_pass_header` configuration using that module's merge behavior.

The result is a classification of configuration intent:

- `hidden`: Nginx is configured not to pass the header.
- `passed`: Nginx is explicitly configured to pass a normally hidden header.
- `not_filtered`: no static filter is visible.
- `conflicting`: visible hide/pass directives cannot be resolved safely.

`not_filtered` does not prove disclosure because the backend might not emit
the header. It can still fail an explicit configuration policy whose purpose
is defense in depth.

### Includes

Includes are already expanded in lexical position. Resolution must therefore
use expanded order and preserve each directive's original `SourceSpan`.
Globbed includes must use the repository's existing deterministic ordering.

An include error marks affected scopes incomplete. It must not cause inherited
headers from the remaining partial tree to be presented as complete evidence.

### Nested Locations and Internal Redirects

Inheritance follows syntactic configuration levels. The implementation does
not simulate URI matching, rewrite phases, named-location jumps, or internal
redirects. A route assessment is attached to the scope containing the
upstream directive. Dynamic reachability is a route-manifest concern deferred
to followup-09.

## Policy Schema Fragment

The fragment below is illustrative YAML for the followup-03 model:

```yaml
schema_version: 1
nginx:
  reverse_proxy_headers:
    profiles:
      public_http:
        applies_to:
          upstream_families: [proxy]
          server_names: ["api.example.test"]
          location_patterns: ["/api/", "~ ^/v[0-9]+/"]
        request_headers:
          required:
            X-Forwarded-For:
              any_of:
                - "$proxy_add_x_forwarded_for"
                - "$remote_addr"
            X-Real-IP:
              any_of: ["$remote_addr"]
            X-Forwarded-Proto:
              any_of: ["$scheme"]
          host:
            allowed_values: ["$host", "$proxy_host"]
            allow_fixed_literals: true
          forbidden_client_variables:
            - "$http_x_forwarded_for"
            - "$http_x_real_ip"
            - "$http_host"
        response_headers:
          must_hide:
            - X-Powered-By
            - X-AspNet-Version
          must_not_pass:
            - Server
            - X-Powered-By
          allow_explicit_pass: []
    unmatched_routes: indeterminate
```

Validation rules:

- Profile IDs are unique.
- Header names use RFC token syntax and are compared case-insensitively.
- `any_of` values are exact normalized token expressions, not regular
  expressions.
- `allowed_values` and `forbidden_client_variables` cannot be empty when
  present.
- `must_hide` and `allow_explicit_pass` cannot contain the same header.
- `unmatched_routes` is `not-applicable`, `fail`, or `indeterminate`;
  `indeterminate` is the recommended default.
- Overlapping profiles are rejected unless they are byte-for-byte equivalent
  after normalization. First-match policy semantics are deliberately avoided.

The first pull request does not support arbitrary regular expressions over
header values. That boundary keeps policy reviewable and prevents a second,
unsafe expression language.

## Assessment Algorithm

For every supported `ProxyRoute`:

1. Match exactly one policy profile.
2. If no profile matches, apply `unmatched_routes`.
3. Resolve request headers and response filters.
4. If the scope is incomplete or resolution contains an unsupported dynamic
   construct needed by the profile, emit `indeterminate`.
5. Evaluate every required request header.
6. Evaluate `Host` independently because Nginx defaults and trust properties
   differ from ordinary forwarding headers.
7. Evaluate every `must_hide`, `must_not_pass`, and approved exception.
8. Emit one assessment per `(control_id, route_id, profile_id)` rather than
   one assessment per missing header.
9. Put all failed predicates and evidence locations in the assessment.

Recommended control IDs:

- `cis-nginx-3.4.proxy-source-identity`
- `cis-nginx-2.5.4.proxy-response-disclosure`
- `policy.nginx.reverse-proxy-host`

The profile can contribute to more than one control assessment. A route can
pass source identity and fail response disclosure without ambiguity.

## Findings Versus Control Assessments

Findings continue to answer "is there an observable security defect under the
project's built-in rule?" Assessments answer "does this scope satisfy the
operator's declared control?"

- Existing proxy findings continue to run with or without policy.
- A failed policy predicate is represented by `ControlAssessment(status=fail)`;
  the first implementation does not create a duplicate policy-violation
  finding.
- An existing finding may be linked through `related_rule_ids` and evidence,
  but is not required for an assessment to fail.
- A policy assessment never suppresses a `policy-review` finding
  automatically. It may link the finding as related evidence, while normal
  suppression remains an explicit, separate user action.
- Finding severity must never be inferred from assessment status.
- A `pass` assessment does not suppress an unconditional finding produced by
  a different, broader rule.

## Default Behavior Without Policy

With no `nginx.reverse_proxy_headers` section:

- no reverse-proxy header `ControlAssessment` records are emitted;
- all existing Nginx findings and rule registry behavior remain byte-for-byte
  stable apart from intentionally shared internal refactoring;
- `--enable-policy-review` keeps its PR #9 behavior;
- coverage percentages and statuses do not change;
- unsupported upstream families do not create new findings.

This compatibility requirement is a release gate.

## Error and Indeterminate Handling

| Condition | Result |
| --- | --- |
| Policy document cannot be loaded or validated | Followup-03 emits an `AnalysisIssue`; no policy assessments are emitted. Existing findings still run if config analysis can continue. |
| Root Nginx config cannot be parsed | Existing fatal analysis behavior; no proxy assessments. |
| Included file missing, cyclic, or malformed in an affected ancestry | Assessment is `indeterminate` with include issue codes and known partial evidence. |
| Dynamic header expression is present but the policy requires an exact value | `indeterminate`, unless the expression is explicitly listed in `any_of`. |
| A required header is explicitly removed with an empty value | `fail`. |
| A header profile does not match any route and `unmatched_routes` is `not-applicable` | No defect claim; emit `not-applicable` only if followup-04 requires explicit records, otherwise omit. |
| Multiple non-equivalent profiles match | Policy validation error, not first-match behavior. |
| Directive appears in illegal context | Ignore it for effective semantics and attach an unsupported-evidence reason; assessment becomes `indeterminate` only if that directive could affect the tested predicate. |
| Unsupported upstream module owns the route | `indeterminate` when explicitly targeted; otherwise no assessment. |

## Likely Files

Only likely implementation locations are listed; followup-03/04 may establish
the final package layout.

- `src/webconf_audit/local/nginx/effective_scope.py` - new generic scope graph.
- `src/webconf_audit/local/nginx/proxy_headers.py` - new upstream adapters and
  effective header resolver.
- `src/webconf_audit/local/nginx/assessments/reverse_proxy_headers.py` - new
  policy evaluator.
- `src/webconf_audit/policy/models.py` - extend the Nginx policy section
  defined by followup-03.
- `src/webconf_audit/models.py` or the followup-04 assessment module - only
  integration, not a second assessment model.
- `src/webconf_audit/local/nginx/rules/proxy_missing_source_ip_headers.py` -
  optionally consume the shared resolver without changing default output.
- `src/webconf_audit/local/nginx/rules/proxy_set_header_host_spoofing.py` -
  optionally consume normalized evidence without changing rule identity.
- `tests/test_nginx_effective_scope.py`
- `tests/test_nginx_reverse_proxy_header_policy.py`
- `tests/fixtures/webserver-configs/nginx/policy/reverse_proxy_headers/`

## Comprehensive Test Design

### Scope and Includes

- Directives declared at `http`, `server`, and `location`.
- Included files contributing setters at each legal context.
- Nested includes and glob includes with deterministic order.
- Missing include and include cycle mark only affected assessments
  `indeterminate`.
- Two server blocks that share `http` defaults but override differently.
- Exact, prefix, regex, named, and nested locations remain separate scopes.
- A `proxy_pass` inside a named location is assessed by that scope.
- An `if in location` containing parser-accepted `proxy_set_header` does not
  override the parent route and is recorded as illegal-context evidence.

### Request Header Inheritance

- No explicit HTTP proxy setters produces documented Nginx defaults.
- `http` setters are inherited by a server and location with no local list.
- One local setter replaces the entire parent list and exposes missing
  inherited headers.
- Repeated header names preserve order and compare case-insensitively.
- Empty value removes the header.
- `$proxy_add_x_forwarded_for` passes when explicitly allowed.
- `$http_x_forwarded_for` fails the forbidden-client-variable boundary.
- `$host`, `$proxy_host`, a fixed literal, and `$http_host` exercise distinct
  `Host` outcomes.
- A substring such as `$http_host_suffix` is not misclassified as
  `$http_host`.
- Quoted multi-token expressions normalize consistently.
- FastCGI, gRPC, and uwsgi adapters use their own directive families and never
  inherit `proxy_set_header`.

### Response Header Filtering

- Built-in hidden HTTP proxy headers are represented as defaults.
- `proxy_hide_header X-Powered-By` satisfies a required hide.
- `proxy_pass_header Server` fails `must_not_pass`.
- Different casing still refers to the same header.
- Parent hide/pass configuration and local overrides follow verified module
  merge semantics.
- A backend header named `X-Server-Info` does not match `Server`.
- A policy exception allows one explicit pass without weakening other
  headers.
- Dynamic header names are unsupported and never treated as a literal match.

### Assessments and Findings

- Source identity pass and disclosure fail produce two independent
  assessments.
- Existing findings remain identical in a no-policy golden test.
- Policy failure does not create a duplicate finding.
- Existing finding IDs appear in `related_rule_ids` when evidence overlaps.
- No profile match follows each `unmatched_routes` mode.
- Multiple profile match is rejected during policy validation.
- Assessment evidence includes root and included file locations.
- Serialization is deterministic.

### False-Positive Boundaries

- A static-file location with no upstream directive is not assessed.
- `auth_request` alone is not treated as a reverse-proxy response route.
- Commented directives and string fragments are ignored by the AST.
- `proxy_set_header X-Forwarded-For ""` is a deliberate removal, not a valid
  forwarding header.
- A safe header on one route does not satisfy a sibling route.
- A response header added by `add_header` is not confused with a header
  received from and filtered for an upstream.
- The analyzer does not assert that an unfiltered disclosure header is
  actually returned at runtime.

## Documentation and Coverage Effects

Implementation should update generated and narrative documentation only when
the code lands:

- `docs/rule-coverage.md` should list any new assessment capability
  separately from executable finding rules.
- `docs/control-source-coverage-tracker.md` should keep CIS 2.5.4 as
  `partial` until runtime/backend evidence or an explicitly accepted static
  boundary supports full credit.
- CIS 3.4 remains `full` for the existing bounded built-in check. The new
  policy assessment is richer operator evidence, not a reason to inflate the
  denominator or numerator.
- `docs/benchmarks-covering.md` should explain that policy-backed assessments
  require an `AuditPolicy`.
- `docs/architecture.md` should document the Nginx scope graph and the
  finding/assessment split.
- CLI/API documentation should include a minimal policy example and the
  default no-policy behavior.

No source coverage percentage changes are part of this followup by default.

## Acceptance Criteria

- An explicit policy can distinguish upstream routes that satisfy or violate
  the declared header contract using effective, source-aware semantics.
- Request-header replacement inheritance is tested at `http`, `server`, and
  `location`.
- Includes retain original evidence locations.
- Illegal `if` context does not change an unconditional route result.
- Response hide/pass behavior is tested for every supported upstream family.
- Missing or partial configuration evidence yields `indeterminate`, never a
  guessed pass.
- Existing findings and default CLI/API output remain stable without policy.
- Policy failures are assessments, not duplicate findings.
- All new policy models reject unknown keys and contradictory settings.
- Documentation makes no new full-coverage claim.
- The implementation passes the full test suite and deterministic inventory
  checks.

## Dependencies

- Followup-03 `AuditPolicy` loading, versioning, strict validation, and CLI/API
  plumbing.
- Followup-04 `ControlAssessment`, serialization, rendering, and status
  aggregation.
- Current include expansion and `SourceSpan` preservation.
- PR #9's distinction between policy review, severity, and coverage strength.
- Official Nginx module documentation and, where documentation is silent,
  the corresponding Nginx Open Source merge functions locked by tests.

## Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Generic scope graph becomes a second parser | Build a read-only view over existing AST nodes; do not duplicate tokenization. |
| Incorrect module inheritance creates false confidence | Encode each directive family separately and cite/test official Nginx behavior. |
| Policy matcher approximates Nginx routing | Match syntactic scopes only; do not claim runtime route reachability. |
| Refactoring changes old finding text or count | Add no-policy golden tests before migrating old rules to shared helpers. |
| Dynamic expressions are over-classified | Require exact allowlisted expressions or return `indeterminate`. |
| CIS 2.5.4 is over-claimed | Keep tracker status `partial` and state the missing runtime/backend boundary. |
| Policy complexity grows into a general DSL | Use exact values and bounded selectors only in v1. |

## Rollback Plan

The feature is additive and policy-gated. Rollback consists of:

1. Stop registering the reverse-proxy assessment evaluator.
2. Remove the `nginx.reverse_proxy_headers` schema section.
3. Leave the generic scope graph only if later followups already depend on it;
   otherwise remove it with its tests.
4. Keep existing proxy findings and PR #9 policy-review behavior unchanged.
5. Revert only documentation that describes this policy capability; do not
   alter the conservative coverage ledger.

No persisted analysis data requires migration because assessments are
derived output.

## Reviewer Checklist

- [ ] The implementation consumes the followup-03/04 models instead of
      defining parallel policy or assessment types.
- [ ] `proxy_set_header` replacement inheritance is exact and list-based.
- [ ] Empty values, Nginx defaults, duplicate names, and case folding are
      handled explicitly.
- [ ] Response hide/pass behavior is module-specific and tested.
- [ ] Includes preserve source file and line evidence.
- [ ] `if in location` does not leak conditional or illegal values into its
      parent route.
- [ ] Dynamic expressions fail closed to `indeterminate`.
- [ ] Findings and assessments are not duplicated or conflated.
- [ ] No-policy behavior has a golden regression test.
- [ ] CIS/ASVS/OWASP mappings use the exact rows listed above.
- [ ] Coverage documentation remains conservative.
- [ ] The change is limited to reverse-proxy header semantics plus the minimal
      reusable scope graph needed by later followups.
