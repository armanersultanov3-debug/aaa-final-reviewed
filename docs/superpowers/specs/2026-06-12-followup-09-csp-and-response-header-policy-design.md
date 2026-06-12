# CSP and Response-Header Policy Design

Date: 2026-06-12
Status: proposed
Sequence: follow-up 09 of 14

## Status and Dependencies

This is the design for followup-09. It is the final policy followup in this
series and deliberately has two coupled responsibilities:

1. provide correct, reusable Nginx effective `add_header` semantics based on
   the PR #9 implementation; and
2. provide a structurally correct CSP model and route-aware response-header
   policy assessment.

The implementation depends on:

- followup-03 for versioned, strictly validated `AuditPolicy`;
- followup-04 for `ControlAssessment`;
- followup-05 for the source-aware Nginx effective-scope graph;
- followup-07 for bounded declared-location selectors and concrete sample-URI
  resolution used by the route manifest;
- PR #9 for proven `add_header`, `add_header_inherit`, `location`, and
  `if in location` behavior in `nginx.http3_alt_svc_review`.

This design consumes those foundations. It does not create a second policy
loader, route matcher, or assessment result model.

## Decision Summary

Implement four reviewable layers:

1. Extract PR #9's effective response-header logic into a shared,
   source-aware Nginx resolver that supports standard replacement inheritance
   and `add_header_inherit on|off|merge`.
2. Replace the current dictionary-oriented CSP helper with an ordered AST
   capable of representing multiple header instances, comma-delimited
   serialized policies, duplicate directives, typed source expressions,
   enforcing versus report-only disposition, and parse issues.
3. Add an optional route manifest to `nginx.response_headers` so header
   expectations are attached to declared response kinds and route scopes
   rather than assumed for every server.
4. Emit policy-backed control assessments for CSP and selected response
   headers while preserving existing findings and explicitly documenting
   intended corrections to previously inaccurate default cases.

The pull request must remain bounded. Version 1 does not implement a complete
browser CSP evaluator, inspect application HTML, prove nonce freshness, match
hashes to response bodies, crawl routes, or migrate every server analyzer to
Nginx scope semantics.

## Current Evidence and Rules

### Current CSP Parser

`src/webconf_audit/csp.py` currently:

- replaces every comma with a semicolon;
- splits on semicolons;
- stores directives in `dict[str, str]`;
- keeps only the first value for a duplicate directive;
- loses policy boundaries, header instances, ordering, source tokens,
  disposition, and parse errors.

This is structurally incorrect for CSP:

- commas separate serialized policies in a CSP policy list;
- semicolons separate directives inside one policy;
- multiple policies are all enforced or reported according to disposition;
- duplicate directives are semantically significant at parse time even when
  later duplicates are ignored;
- report-only policy must not satisfy an enforcement requirement.

The parser is also shared by external, Apache, IIS, Lighttpd, and generic
header helpers, so replacement needs compatibility adapters and bounded
migration.

### Current Nginx Header Semantics

Most Nginx header rules use `find_server_add_headers`, which:

- evaluates only `http` and direct `server` scope;
- applies the legacy replacement rule only;
- does not inspect `location` or `if in location`;
- does not model `add_header_inherit`;
- does not represent `always` as status-code applicability;
- cannot show conditional branches where a child drops a parent header.

PR #9 added a local, better implementation in
`nginx.http3_alt_svc_review`:

- response scopes include `server`, nested `location`, and `if in location`;
- standard replacement inheritance is supported;
- `add_header_inherit on|off|merge` is supported;
- source file and line survive includes;
- effective values are grouped by response scope.

That implementation is intentionally local to the HTTP/3 review rule and now
needs extraction without changing HTTP/3 output.

### Current Header Findings

The relevant Nginx findings include:

- `nginx.missing_content_security_policy`
- `nginx.content_security_policy_unsafe`
- `nginx.content_security_policy_missing_frame_ancestors`
- `nginx.content_security_policy_missing_reporting_endpoint`
- `nginx.csp_value_review`
- `nginx.missing_referrer_policy`
- `nginx.referrer_policy_unsafe`
- `nginx.missing_x_content_type_options`
- `nginx.missing_permissions_policy`
- `nginx.permissions_policy_unsafe`
- `nginx.missing_hsts_header`
- `nginx.hsts_header_unsafe`
- `nginx.missing_x_frame_options`
- `nginx.crlf_in_add_header`

External probes additionally detect CSP presence, selected unsafe tokens,
`object-src`, `base-uri`, reporting configuration, repeated nonce values
across responses, and selected HTML/SRI relationships.

The coverage tracker currently states:

- CIS NGINX sections 5.3.2 and 5.3.3 are `partial`;
- ASVS V3.4.3 CSP quality is `partial`;
- ASVS V3.4.5 Referrer-Policy is `full`;
- ASVS V3.4.6 framing policy is `full`;
- ASVS V3.4.7 reporting endpoint presence is `full` within the documented
  configuration-visible boundary.

This followup adds policy precision. It does not silently redefine those
coverage boundaries.

## Exact Control Rows

The following exact rows govern mappings and documentation:

| Source | Row | Exact row text | Intended evidence |
| --- | --- | --- | --- |
| CIS NGINX Benchmark v3.0.0 | 5.3.2 | Ensure that Content Security Policy (CSP) is enabled and configured properly | Effective enforcing CSP on selected response routes, parsed against an explicit application policy. |
| CIS NGINX Benchmark v3.0.0 | 5.3.3 | Ensure the Referrer Policy is enabled and configured properly | Effective Referrer-Policy values and status-code applicability on selected routes. |
| OWASP ASVS 5.0.0 | V3.4.1, L1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | Effective HSTS on HTTPS response scopes; preload remains optional policy. |
| OWASP ASVS 5.0.0 | V3.4.2, L1 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | Only bounded fixed-value or approved-variable response-header evidence; application sensitivity and validation remain external. |
| OWASP ASVS 5.0.0 | V3.4.3, L2 | Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined. | CSP AST, explicit minimum directives, and configured script authorization strategy. Per-response freshness/body matching remain external. |
| OWASP ASVS 5.0.0 | V3.4.4, L2 | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser. | Effective exact value and all-response applicability. |
| OWASP ASVS 5.0.0 | V3.4.5, L2 | Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname. | Effective allowed Referrer-Policy values. HTML attributes remain out of scope. |
| OWASP ASVS 5.0.0 | V3.4.6, L2 | Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon. | Effective CSP `frame-ancestors` by route; X-Frame-Options is transitional evidence only. |
| OWASP ASVS 5.0.0 | V3.4.7, L3 | Verify that the Content-Security-Policy header field specifies a location to report violations. | `report-uri`, or `report-to` linked to a visible reporting endpoint declaration. Delivery remains external. |
| OWASP ASVS 5.0.0 | V3.4.8, L3 | Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting. | Route-manifest document responses and effective COOP value. |
| OWASP Top 10:2021 | A05:2021 | Security Misconfiguration | Primary current repository category. |
| OWASP Top 10:2025 | A02:2025 | Security Misconfiguration | Current-edition companion mapping. |
| OWASP Cheat Sheet Series | Content Security Policy Cheat Sheet | Content Security Policy Cheat Sheet | Primary CSP guidance. |
| OWASP Cheat Sheet Series | HTTP Security Response Headers Cheat Sheet | HTTP Security Response Headers Cheat Sheet | General header guidance. |
| OWASP Cheat Sheet Series | Clickjacking Defense Cheat Sheet | Clickjacking Defense Cheat Sheet | `frame-ancestors` companion guidance. |
| OWASP Cheat Sheet Series | HTTP Strict Transport Security Cheat Sheet | HTTP Strict Transport Security Cheat Sheet | HSTS companion guidance. |

The non-ASCII hyphens in ASVS V3.4.8 are preserved because the row is quoted
verbatim from the official ASVS v5.0.0 CSV.

## Normative CSP Semantics to Preserve

The CSP AST and evaluator are based on the W3C Content Security Policy Level 3
model:

- a response can contain more than one CSP header field;
- each header field value is a comma-delimited list of serialized policies;
- each policy contains a semicolon-delimited ordered directive set;
- every enforcing policy is enforced;
- every report-only policy is monitored but not enforced;
- adding an enforcing policy can only further restrict effective behavior;
- duplicate directives after the first directive of that name are ignored by
  policy parsing, but should remain visible as diagnostics;
- CSP directive names are ASCII case-insensitive;
- source expressions have typed syntax, including keywords, nonces, hashes,
  schemes, hosts, and wildcards;
- directive fallback behavior is directive-specific;
- `frame-ancestors` and `base-uri` do not gain a generic `default-src`
  fallback;
- `report-uri` is deprecated in favor of `report-to`;
- `report-to` names a reporting group and requires response reporting
  infrastructure to identify a location;
- `Content-Security-Policy-Report-Only` does not satisfy an enforcing CSP
  requirement.

The implementation must not create one synthetic merged directive dictionary.
Multiple policies are retained and evaluated as a conjunction of policy
effects.

## Official Nginx Header Semantics to Preserve

- `add_header` is valid in `http`, `server`, `location`, and
  `if in location`.
- Several `add_header` directives can exist at one level.
- Under standard inheritance, parent headers are inherited if and only if no
  `add_header` exists at the current level.
- `add_header_inherit on` keeps standard inheritance.
- `add_header_inherit off` cancels inherited headers.
- `add_header_inherit merge` appends inherited values to current-level
  values.
- The inheritance mode is itself inherited and can be redefined.
- `add_header_inherit` appeared in Nginx 1.29.3.
- Without `always`, Nginx adds a header only for response status codes:
  `200`, `201`, `204`, `206`, `301`, `302`, `303`, `304`, `307`, and `308`.
- With `always`, the header is added regardless of response code.
- Header names compare case-insensitively, while multiple values and
  declaration order remain evidence.
- `if in location` is a conditional response scope and must not be flattened
  into its parent.

## Gaps to Close

1. CSP policy-list commas are currently destroyed.
2. Multiple headers and multiple policies cannot be represented.
3. Enforcing and report-only CSP are conflated.
4. Directive ordering, duplicates, typed sources, and parse issues are lost.
5. Nonce/hash syntax and static-versus-dynamic strategy are not modeled.
6. Current unsafe-token checks can be wrong when multiple enforcing policies
   combine restrictively.
7. `report-to` is not linked to a visible endpoint declaration.
8. Most Nginx header rules miss location and conditional branch overrides.
9. `add_header_inherit merge|off` is only implemented locally in the HTTP/3
   review rule.
10. Header presence does not imply delivery on error responses without
    `always`.
11. A header that is correct for HTML may be unnecessary or harmful for an
    API, download, redirect, or internal route.
12. Static Nginx configuration cannot prove nonce freshness, hash/body
    correspondence, actual response content type, or runtime header rewrites.
13. Existing findings and policy assessments need a migration boundary that
    corrects known semantic errors without creating a broad, unreviewable
    cross-server rewrite.

## Goals

- Introduce a correct ordered CSP AST.
- Preserve multiple header instances and policy dispositions.
- Parse and classify nonce, hash, keyword, scheme, host, wildcard, dynamic,
  unknown, and invalid source expressions.
- Resolve effective Nginx response headers at every material response scope.
- Reuse and preserve PR #9 `add_header_inherit` behavior.
- Model `always` and status-code applicability.
- Add an explicit route manifest and response-kind profiles.
- Evaluate CSP minimums, script authorization strategy, framing, reporting,
  Referrer-Policy, HSTS, X-Content-Type-Options, COOP, Permissions-Policy, and
  bounded generic header requirements.
- Keep report-only rollout evidence separate from enforcement.
- Emit deterministic, source-aware control assessments.
- Make intended default finding corrections explicit and tested.

## Non-Goals and Reviewability Boundaries

The version 1 pull request must not:

- implement the complete CSP3 fetch, navigation, inline, worker, and
  WebAssembly algorithms;
- compute a general mathematical intersection for arbitrary CSP source lists;
- inspect HTML `meta` CSP;
- fetch pages or parse response bodies;
- prove nonce entropy, unpredictability, or per-response freshness;
- prove a hash matches an inline or external resource;
- prove Reporting API endpoint delivery;
- execute Nginx variables, `map`, njs, Lua, or application templating;
- discover routes or content types automatically;
- simulate rewrites, `try_files`, error pages, or internal redirects;
- migrate Apache, IIS, Lighttpd, and external CSP rules to new scope semantics
  in the same pull request;
- add a general browser-policy DSL;
- make X-Frame-Options substitute for ASVS V3.4.6;
- claim full CSP semantic verification.

The reviewable implementation sequence is:

1. shared Nginx response-header resolver plus HTTP/3 parity;
2. CSP AST plus compatibility adapters;
3. policy schema and Nginx assessments;
4. bounded migration of existing Nginx CSP/header findings;
5. docs and tests.

Each layer must be independently testable.

## Foundation Contract

The evaluator consumes:

```text
AuditPolicy
  schema_version
  nginx.response_headers | null
```

Every assessment includes at least:

- `policy_section: "nginx.response_headers"`
- `route_id`
- `profile_id`
- `server_scope_id`
- `response_scope_id`
- route response kind and declared statuses;
- effective header instances and their applicability;
- enforcing and report-only CSP policy sets;
- relevant CSP predicate results;
- parse issues, dynamic evidence, and completeness;
- source locations and inheritance origins.

Output belongs in `AnalysisResult.control_assessments`. The route manifest is
policy input, not analyzer metadata inferred from the application.

## Proposed CSP AST

### Policy Set

```python
class CspDisposition(str, Enum):
    ENFORCE = "enforce"
    REPORT = "report"


class CspPolicySet:
    header_instances: tuple["CspHeaderInstance", ...]
    policies: tuple["CspPolicy", ...]
    issues: tuple["CspParseIssue", ...]
```

One policy set is built for the effective
`Content-Security-Policy` and
`Content-Security-Policy-Report-Only` header instances at one response scope.

### Header Instance

```python
class CspHeaderInstance:
    header_name: str
    disposition: CspDisposition
    raw_value: str
    policies: tuple["CspPolicy", ...]
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str
    applicability: "HeaderApplicability"
```

A single Nginx `add_header` can contain a comma-delimited serialized policy
list and therefore produce multiple `CspPolicy` nodes.

### Policy and Directive

```python
class CspPolicy:
    disposition: CspDisposition
    raw_text: str
    policy_index: int
    directives: tuple["CspDirective", ...]
    issues: tuple["CspParseIssue", ...]

    def first_directive(self, name: str) -> "CspDirective | None": ...


class CspDirective:
    name: str
    raw_name: str
    raw_value: str
    tokens: tuple["CspToken", ...]
    directive_index: int
    effective: bool
    duplicate_of: int | None
```

All directives are preserved. The first directive of a normalized name is
`effective=True`; later duplicates are retained with `effective=False`.

### Typed Source Expressions

```python
class CspTokenKind(str, Enum):
    KEYWORD = "keyword"
    NONCE = "nonce"
    HASH = "hash"
    SCHEME = "scheme"
    HOST = "host"
    WILDCARD = "wildcard"
    DYNAMIC_TEMPLATE = "dynamic_template"
    TOKEN = "token"
    UNKNOWN = "unknown"
    INVALID = "invalid"


class CspToken:
    kind: CspTokenKind
    raw: str
    normalized: str
    valid: bool
```

Specialized token payloads:

- nonce: static/dynamic, variable names, and a non-reversible fingerprint for
  any static value shown in output;
- hash: algorithm `sha256`, `sha384`, or `sha512`, base64 syntax status, and
  fingerprint;
- host: scheme, host, port, path, and wildcard components when parseable;
- keyword: normalized known keyword;
- dynamic template: raw Nginx expression plus extracted exact variable names.

Unknown registered or future CSP extensions are preserved as `UNKNOWN`, not
discarded.

### Parse Issues

```python
class CspParseIssue:
    code: str
    message: str
    policy_index: int | None
    directive_index: int | None
    token_index: int | None
    fatal_for_structure: bool
```

Examples:

- empty policy member;
- invalid directive name;
- duplicate directive;
- invalid nonce or hash syntax;
- unsupported dynamic policy separator;
- unknown directive or source expression.

Unknown syntax is not automatically fatal. Predicate evaluation decides
whether it affects the requested control.

## CSP Parsing Rules

1. Accept one header instance value at a time.
2. Strip only Nginx configuration quoting already represented by AST tokens;
   do not treat CSP single quotes as generic string delimiters.
3. Split the serialized policy list on CSP commas.
4. Split each policy on semicolons.
5. Split each non-empty directive on ASCII whitespace.
6. Normalize directive names to lowercase.
7. Preserve raw text, order, and empty members as diagnostics.
8. Mark duplicate directives after the first as ignored/effective false.
9. Parse source-list directives into typed tokens.
10. Preserve non-source-list directive values with directive-specific token
    parsers where needed, such as `report-to`, `report-uri`, and `sandbox`.
11. Never perform the current global comma-to-semicolon replacement.
12. If the raw Nginx value contains variables that could expand to commas or
    semicolons, parse the visible static structure and mark affected
    boundaries dynamic; do not claim a complete parse.

Compatibility helpers such as `content_security_policy_directives()` may
remain temporarily, but they must be documented as a first-policy adapter and
must not be used by new Nginx policy evaluation.

## CSP Directive Semantics in Version 1

### Explicit ASVS Minimums

For ASVS V3.4.3, version 1 checks:

- at least one effective enforcing CSP policy;
- an explicit effective `object-src` directive whose only source is
  `'none'`;
- an explicit effective `base-uri` directive whose only source is `'none'`;
- one configured script authorization strategy:
  - approved host/scheme allowlist;
  - nonce;
  - hash;
  - nonce or hash;
  - strict CSP strategy using nonce/hash plus `'strict-dynamic'`.

The requirement is explicit even though some fetch directives have
`default-src` fallback, because the ASVS row explicitly calls for
`object-src 'none'` and `base-uri 'none'`.

### Fallbacks

Implement only the fallback chains required by version 1 predicates:

- `script-src-elem` -> `script-src` -> `default-src`;
- `script-src-attr` -> `script-src` -> `default-src`;
- `script-src` -> `default-src`;
- `object-src` -> `default-src` for behavioral diagnostics, but not for the
  explicit ASVS minimum;
- no fallback for `base-uri`;
- no fallback for `frame-ancestors`;
- reporting directives do not inherit from another CSP directive.

Fallback results must identify the directive that supplied the value.

### Multiple Enforcing Policies

Do not flatten policies. For version 1:

- presence requires at least one enforcing policy;
- explicit `object-src 'none'` passes if at least one enforcing policy
  contains it, because all policies are enforced and another policy cannot
  weaken it;
- explicit `base-uri 'none'` follows the same monotone rule;
- a default-deny `frame-ancestors 'none'` passes if at least one enforcing
  policy contains it;
- generic inline script is effectively allowed only when every enforcing
  policy allows generic inline execution;
- eval is effectively allowed only when every enforcing policy allows eval;
- a designated baseline policy must satisfy the configured allowlist or
  nonce/hash strategy;
- additional enforcing policies must be parseable for relevant directives and
  cannot be treated as weakening the baseline;
- if additional policies make application behavior stricter or incompatible,
  record an operational compatibility warning in assessment evidence rather
  than declaring weaker security.

General host-source intersection, path intersection, and all CSP3 request
algorithms are out of scope. If a requested predicate requires them, return
`indeterminate`.

### Report-Only Policies

- Report-only policies are parsed into the same AST with disposition
  `report`.
- They never satisfy `enforcement.required`.
- They may satisfy a separate rollout requirement such as
  `report_only.required`.
- A report-only policy can be compared with the target baseline for migration
  readiness, but that result is not an enforcement pass.
- Reporting endpoints for enforcing and report-only policies are assessed
  independently.

### Nonces

Classify nonce sources as:

- `static_literal`: syntactically valid, fixed in configuration;
- `dynamic_template`: contains one or more Nginx variables;
- `invalid`;
- `unknown`.

Policy behavior:

- A static literal fails a per-response nonce requirement because Nginx will
  emit the same configured token unless another unmodeled layer rewrites it.
- A dynamic template can satisfy the configuration-strategy predicate only
  when all variables are policy-approved.
- A dynamic template cannot prove entropy, unpredictability, or freshness.
- ASVS L3 remains partial unless runtime evidence corroborates distinct
  per-response values.
- Assessment output fingerprints static nonce values and does not echo them
  verbatim.

### Hashes

- Recognize `sha256`, `sha384`, and `sha512` hash sources.
- Validate encoded-value syntax.
- Compare hashes to an optional approved-hash inventory.
- Do not prove correspondence with inline or external resource bodies.
- Assessment output may show algorithm and fingerprint, not a needlessly
  repeated full digest.

### Reporting

Reporting passes when policy requirements are met by one of:

- an effective non-empty `report-uri` URI reference; or
- an effective `report-to <group>` plus an effective response header that
  maps that group to one or more endpoint URLs using supported reporting
  syntax.

Version 1 may support:

- `Reporting-Endpoints` as the preferred response header;
- legacy `Report-To` only behind an explicit policy allowance.

The evaluator checks configuration linkage, not endpoint reachability,
delivery, retention, or alerting.

## Proposed Nginx Response-Header Models

### Header Instance

```python
class EffectiveResponseHeader:
    normalized_name: str
    configured_name: str
    raw_value_tokens: tuple[str, ...]
    rendered_static_value: str
    always: bool
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str
    origin: Literal["explicit", "inherited", "merged"]
    dynamic_variables: tuple[str, ...]
```

### Applicability

```python
class HeaderApplicability:
    all_statuses: bool
    known_statuses: frozenset[int]
    conditional_branch_id: str | None
```

For `always=False`, `known_statuses` is the documented Nginx status set.
For `always=True`, `all_statuses=True`.

### Response Scope

```python
class EffectiveResponseScope:
    scope_id: str
    base_headers: tuple[EffectiveResponseHeader, ...]
    conditional_branches: tuple["EffectiveResponseBranch", ...]
    inherit_mode: Literal["on", "off", "merge"]
    complete: bool
    indeterminate_reasons: tuple[str, ...]
```

An `if in location` is a child branch. It does not replace the base response
scope globally.

### Resolver Behavior

For each legal scope:

1. Resolve inherited `add_header_inherit`, default `on`.
2. Collect all local `add_header` directives.
3. Apply:
   - `off`: local only;
   - `merge`: local followed by inherited, matching PR #9;
   - `on`: local list if non-empty, otherwise inherited list.
4. Preserve duplicate names and declaration order.
5. Parse the final `always` token only when it occupies the Nginx parameter
   position; a CSP text token containing the word `always` is not the flag.
6. Create separate branch scopes for `if in location`.
7. Preserve source file and line across includes.

The extracted resolver must produce the same HTTP/3 review observations as
PR #9 before other rules migrate.

## Route Manifest

The route manifest is required for route-specific policy assessments. It is a
bounded policy structure, not application route discovery.

```python
class ResponseRoute:
    route_id: str
    server_names: tuple[str, ...]
    declared_location: LocationSelector | None
    sample_uris: tuple[str, ...]
    response_kind: Literal[
        "html_document", "api", "static_asset", "download",
        "redirect", "error", "internal", "custom"
    ]
    schemes: frozenset[Literal["http", "https"]]
    expected_statuses: frozenset[int]
    profile_id: str
```

Rules:

- Every route has a stable unique ID and exactly one profile.
- A route provides a declared location, sample URIs, or both.
- `response_kind` controls which specialized headers are applicable.
- `expected_statuses` drives `always` evaluation.
- Empty status sets are rejected.
- The manifest does not assert that the application actually emits those
  statuses or content types; it declares the review contract.
- Unlisted route behavior is explicit:
  `ignore`, `indeterminate`, or `fail`.
- Rewrites and internal redirects follow the boundary from followup-07 and are
  `indeterminate` by default.

HTML-only controls such as CSP and COOP are not automatically required for
API or download routes unless their profile says so. Headers such as
X-Content-Type-Options may be required for all response kinds.

## Policy Schema Fragment

```yaml
schema_version: 1
nginx:
  response_headers:
    route_manifest:
      - id: app-html
        server_names: ["www.example.test"]
        declared_location:
          modifier: prefix
          pattern: /
        sample_uris: ["/", "/account"]
        response_kind: html_document
        schemes: [https]
        expected_statuses: [200, 302, 404, 500]
        profile: browser-document
      - id: api-v1
        server_names: ["api.example.test"]
        sample_uris: ["/v1/users", "/v1/orders"]
        response_kind: api
        schemes: [https]
        expected_statuses: [200, 400, 401, 403, 404, 429, 500]
        profile: api-response
    profiles:
      browser-document:
        conditional_branches: require_all
        csp:
          enforcement:
            required: true
            baseline_policy: any_enforcing
            additional_policies: require_parseable
          required_directives:
            object-src: ["'none'"]
            base-uri: ["'none'"]
          script_authorization:
            mode: nonce_or_hash
            allowed_nonce_variables: ["$csp_nonce"]
            allow_static_nonce: false
            allowed_hashes: []
            allow_host_allowlist_fallback: false
            require_strict_dynamic: false
          forbidden_effective_capabilities:
            - unsafe-eval
            - generic-unsafe-inline
          frame_ancestors:
            mode: deny
          reporting:
            required: true
            modes: [report-to, report-uri]
            allowed_groups: [csp]
            allowed_endpoint_origins: ["https://reports.example.test"]
          report_only:
            required: false
        headers:
          Referrer-Policy:
            required: true
            allowed_values:
              - no-referrer
              - strict-origin-when-cross-origin
            require_all_expected_statuses: true
          X-Content-Type-Options:
            required: true
            allowed_values: [nosniff]
            require_all_expected_statuses: true
          Cross-Origin-Opener-Policy:
            required: true
            allowed_values: [same-origin, same-origin-allow-popups]
            require_all_expected_statuses: true
          Strict-Transport-Security:
            required_on_schemes: [https]
            min_max_age: 31536000
            include_subdomains: true
            require_all_expected_statuses: true
          X-Frame-Options:
            mode: transitional_optional
      api-response:
        conditional_branches: require_all
        csp:
          enforcement:
            required: false
        headers:
          X-Content-Type-Options:
            required: true
            allowed_values: [nosniff]
            require_all_expected_statuses: true
          Referrer-Policy:
            required: true
            allowed_values: [no-referrer]
            require_all_expected_statuses: true
    reporting_endpoints:
      csp:
        allowed_urls: ["https://reports.example.test/csp"]
    unmatched_routes: indeterminate
    unresolved_internal_redirects: indeterminate
```

### Schema Validation

- Route IDs and profile IDs are unique.
- Every route references an existing profile.
- Server/location selectors reuse followup-07 validation.
- Expected statuses are integers from 100 through 599.
- Header names use valid HTTP field-name token syntax.
- Header value checks are exact or use a built-in typed validator; arbitrary
  user regular expressions are not supported in version 1.
- `required_directives` uses known CSP directive names and non-empty token
  lists.
- Nonce variables are exact Nginx variable names.
- Hash inventory values are syntactically valid CSP hash sources.
- A nonce/hash mode cannot have an empty allowed strategy.
- `baseline_policy` is `any_enforcing` or `each_enforcing`.
- `additional_policies` is `allow`, `require_parseable`, or `forbid`.
- Report-only requirements are separate from enforcement requirements.
- Reporting groups and endpoints are internally consistent.
- HSTS is not required on routes declared HTTP-only unless policy explicitly
  requests it.
- X-Frame-Options cannot satisfy a required CSP `frame-ancestors`.
- Overlapping non-equivalent route entries are rejected.
- Unknown keys are rejected.

## Response-Header Assessment Semantics

### Scope and Conditional Branches

For each route:

1. Resolve its base response scope.
2. Resolve every syntactically reachable `if in location` response branch.
3. Evaluate the profile against the base and branches.
4. With `conditional_branches: require_all`, every branch must satisfy the
   profile.
5. A constant-false condition may be excluded only if the analyzer can prove
   it without evaluating variables.
6. Dynamic conditions remain potentially reachable.

This prevents a child `add_header` inside `if` from silently dropping inherited
security headers on one response path.

### Status Applicability

For every required header:

- compare the route's `expected_statuses` with the header's applicability;
- `always` covers all expected statuses;
- without `always`, only the documented Nginx status set is covered;
- if an uncovered expected status is required, assessment fails;
- if expected statuses are unknown, profile can require `always` or return
  `indeterminate`.

Presence on a 200 response cannot satisfy an "all responses" control when the
route manifest includes 404 or 500.

### Multiple Header Instances

- Preserve all effective instances.
- Header-specific combination semantics apply:
  - CSP: parse every instance and every serialized policy;
  - Referrer-Policy: evaluate the ordered comma-list fallback semantics;
  - generic single-value headers: reject conflicting effective values unless
    the profile explicitly allows multiple;
  - reporting headers: parse supported structured syntax;
  - Set-Cookie and other unrelated multi-value fields are outside this
    policy.
- An empty static value cannot satisfy presence.
- A dynamic value is exact only when policy allows the expression; otherwise
  it is `indeterminate`.

### Specialized Header Validators

Version 1 provides bounded validators for:

- CSP and CSP-Report-Only;
- Referrer-Policy;
- X-Content-Type-Options;
- Strict-Transport-Security;
- Cross-Origin-Opener-Policy;
- Permissions-Policy using existing conservative syntax support;
- X-Frame-Options as transitional evidence;
- Reporting-Endpoints and optional legacy Report-To;
- fixed or approved-variable Access-Control-Allow-Origin.

Generic exact-value requirements remain available for other headers. A
generic validator must not claim semantic understanding.

## CSP Assessment Algorithm

For each route response scope and branch:

1. Select effective enforcing and report-only CSP header instances.
2. Parse every instance into `CspPolicySet`.
3. If enforcement is required and no non-empty enforcing policy exists,
   `fail`.
4. Identify baseline policy candidates according to `baseline_policy`.
5. Check explicit `object-src 'none'` and `base-uri 'none'`.
6. Resolve the script directive and evaluate the configured authorization
   strategy.
7. Evaluate effective unsafe-inline and unsafe-eval capabilities across all
   enforcing policies using conjunction semantics.
8. Evaluate `frame-ancestors`.
9. Evaluate reporting directives and response endpoint linkage.
10. Evaluate report-only rollout requirements separately.
11. Compare status applicability for every CSP header instance used as
    evidence.
12. Return:
    - `pass` only when all requested predicates have sound static evidence;
    - `fail` for complete evidence of absence, malformed required syntax,
      forbidden static capability, static nonce where dynamic is required, or
      uncovered required status;
    - `indeterminate` for relevant dynamic structure, incomplete includes,
      unsupported CSP intersection, or unresolved route behavior.

Recommended control IDs:

- `cis-nginx-5.3.2.csp`
- `cis-nginx-5.3.3.referrer-policy`
- `asvs-5.0.0-v3.4.3.csp-quality`
- `asvs-5.0.0-v3.4.6.frame-ancestors`
- `asvs-5.0.0-v3.4.7.csp-reporting`
- `policy.nginx.response-headers.<profile_id>`

Header-specific ASVS assessments should remain separate so one missing COOP
does not obscure a passing CSP minimum.

## Findings Versus Control Assessments

Findings continue to represent built-in, broadly applicable defects.
Assessments represent whether an explicit route/profile policy is satisfied.

- Existing rule IDs and severities remain.
- Policy mismatches are assessments, not duplicate findings in version 1.
- Existing findings may be linked through `related_rule_ids`.
- `nginx.csp_value_review` remains available under
  `--enable-policy-review` where no explicit CSP profile applies.
- Where an explicit policy assesses the same CSP scope, the generic review
  finding is suppressed for that subject.
- A policy pass does not suppress an unconditional malformed-header, CRLF, or
  other finding.
- Assessment status never changes finding severity.

### Intentional Default Finding Corrections

Unlike followup-05 through followup-08, this followup must correct known
semantic errors in shared CSP/header interpretation. With no policy,
assessment output remains absent, but finding output may intentionally change
only for these reviewed cases:

- comma-delimited CSP policies are no longer treated as semicolon directives;
- report-only CSP no longer satisfies an enforcing CSP requirement;
- duplicate CSP directives use first-directive semantics;
- multiple enforcing policies are evaluated conjunctively for supported
  unsafe capabilities;
- Nginx location and `if in location` header replacement can reveal a missing
  header hidden by the previous server-only check;
- `add_header_inherit off|merge` changes effective values as documented;
- required all-response findings can account for `always`.

Every intentional delta must have a named regression test and release-note
entry. Outside those cases, no-policy finding counts and text should remain
stable.

## Default Behavior Without Policy

With no `nginx.response_headers` section:

- no response-header or CSP control assessments are emitted;
- no route manifest is inferred;
- all existing rules remain enabled under their current default or
  `policy-review` selection;
- HTTP/3 review output remains equivalent after helper extraction;
- only the enumerated semantic corrections above may change findings;
- rule IDs, severities, categories, and standards mappings remain stable
  unless a correction requires a more precise mapping note;
- coverage percentages do not change automatically.

This bounded compatibility contract is a release gate.

## Error and Indeterminate Handling

| Condition | Result |
| --- | --- |
| Invalid policy document or response-header section | Followup-03 `AnalysisIssue`; no policy assessments. |
| Root Nginx parse failure | Existing fatal behavior; no assessments. |
| Missing/cyclic/malformed include affecting a response scope | Affected assessments `indeterminate`. |
| CSP header absent where enforcement required | `fail`. |
| Only report-only CSP exists where enforcement required | `fail`; report-only assessment may pass separately. |
| Required CSP directive is syntactically malformed and therefore ineffective | `fail` when parse semantics are known. |
| Entire or relevant policy structure depends on dynamic separators/tokens | `indeterminate`. |
| Static nonce used where per-response nonce required | `fail`. |
| Approved dynamic nonce variable configured | Configuration predicate may pass with explicit runtime-freshness limitation. |
| Hash syntax valid but body relationship unobserved | Configuration predicate may pass; ASVS evidence remains partial. |
| Multiple policies require unsupported source-list intersection | `indeterminate` for that predicate only. |
| `report-to` group has no visible endpoint mapping | `fail` for reporting requirement. |
| Reporting endpoint is configured but reachability unknown | Configuration predicate can pass with external-delivery limitation. |
| Required header lacks `always` for an expected error status | `fail`. |
| Route expected statuses are unknown and policy requires all responses | `indeterminate` unless every required header uses `always`. |
| Dynamic header value is not explicitly approved | `indeterminate`. |
| Directive appears in illegal context | Exclude from effective semantics and preserve unsupported evidence. |
| Conditional branch lacks a required header | `fail` under `require_all`; otherwise follow explicit branch policy. |
| Unresolved rewrite/internal redirect can change final response scope | Default `indeterminate`. |

## Likely Files

### CSP Core

- `src/webconf_audit/csp.py` - replace internals with AST parser or retain
  compatibility exports over a new parser.
- `src/webconf_audit/csp_ast.py` - optional new AST and tokenizer module if
  keeping `csp.py` small.
- `src/webconf_audit/header_policy.py` - migrate bounded helpers to the new
  AST without broad cross-server behavior changes.

### Nginx

- `src/webconf_audit/local/nginx/effective_scope.py` - reuse followup-05.
- `src/webconf_audit/local/nginx/location_matcher.py` - reuse followup-07.
- `src/webconf_audit/local/nginx/response_header_semantics.py` - new shared
  effective `add_header` resolver.
- `src/webconf_audit/local/nginx/assessments/response_headers.py` - new route
  and profile evaluator.
- `src/webconf_audit/local/nginx/rules/http3_alt_svc_review.py` - migrate to
  shared resolver with parity.
- `src/webconf_audit/local/nginx/rules/header_utils.py` - compatibility facade
  or bounded migration.
- Existing Nginx CSP/header rules listed in Current Evidence - migrate only
  where required for enumerated semantic corrections.

### Policy and Tests

- `src/webconf_audit/policy/models.py` - add route manifest, CSP, and header
  profile models.
- `tests/test_csp_ast.py`
- `tests/test_nginx_response_header_semantics.py`
- `tests/test_nginx_response_header_policy.py`
- `tests/test_nginx_csp_policy.py`
- `tests/test_nginx_http3_alt_svc_review.py` - parity coverage.
- `tests/fixtures/webserver-configs/nginx/policy/response_headers/`

Cross-server rule migrations should be separate followups unless compatibility
adapters can preserve their tested behavior.

## Comprehensive Test Design

### CSP Policy-List Parsing

- One header, one policy, one directive.
- Semicolon-delimited directives.
- Comma-delimited policies in one header value.
- Multiple header instances, each with one or multiple policies.
- Empty directive members and trailing semicolons.
- Empty policy-list members and malformed commas.
- ASCII case-insensitive directive names.
- Source order preservation.
- First duplicate directive effective, later duplicates retained as ignored.
- Unknown directives and tokens preserved.
- Nginx variable in a directive value.
- Nginx variable that could expand to a comma or semicolon makes structure
  incomplete.
- Compatibility adapter returns documented first-policy behavior and is not
  used by new Nginx policy code.

### CSP Source Expressions

- `'none'`, `'self'`, `'unsafe-inline'`, `'unsafe-eval'`,
  `'strict-dynamic'`, `'unsafe-hashes'`, `'report-sample'`, and
  `'wasm-unsafe-eval'`.
- Bare and quoted invalid keyword forms.
- `https:`, explicit origins, ports, paths, subdomain wildcards, and bare `*`.
- `data:` and `blob:`.
- Valid and invalid nonce syntax.
- Static nonce fingerprinting without raw output.
- Dynamic nonce such as `'nonce-$csp_nonce'`.
- Multiple variables in a nonce template.
- Valid SHA-256, SHA-384, and SHA-512 sources.
- Invalid algorithm and invalid encoded value.
- Host/token text containing a comma or semicolon boundary.

### Directive and Fallback Semantics

- Explicit `object-src 'none'`.
- `default-src 'none'` behavioral fallback does not satisfy explicit ASVS
  object-src minimum.
- Explicit `base-uri 'none'` and absence.
- `script-src-elem`, `script-src`, and `default-src` fallback order.
- No `default-src` fallback for `frame-ancestors`.
- Duplicate `script-src` uses the first.
- Empty source list behavior.
- Unknown directive does not invalidate unrelated minimums.

### Multiple Enforcing Policies

- Two policies both enforced.
- Restrictive `connect-src 'none'` in one policy cannot be weakened by another
  policy.
- Generic unsafe-inline is considered effective only if all enforcing
  policies allow it.
- Unsafe-eval follows the same conjunction rule.
- One policy provides explicit `object-src 'none'`; another omits object-src.
- One policy provides `frame-ancestors 'none'`; another is more permissive.
- Conflicting nonce strategies are identified as operationally restrictive,
  not security-permissive.
- Unsupported host-source intersection returns indeterminate only for the
  affected allowlist predicate.
- `additional_policies` modes `allow`, `require_parseable`, and `forbid`.

### Report-Only and Reporting

- Enforcing only.
- Report-only only.
- Both dispositions at one scope.
- Report-only does not satisfy enforcement.
- Required report-only rollout policy.
- `report-uri` one and multiple endpoints.
- `report-to` group with matching `Reporting-Endpoints`.
- Missing group, missing endpoint header, wrong group, disallowed origin.
- Legacy `Report-To` allowed and forbidden by policy.
- Endpoint configuration passes while delivery remains explicitly unproven.

### Nonce and Hash Policy

- Static literal nonce fails dynamic requirement.
- Approved dynamic variable passes configuration strategy with limitation.
- Unapproved or unknown dynamic variable is indeterminate/fail according to
  policy.
- Valid hash in approved inventory.
- Valid hash not in approved inventory.
- Valid hash with no inventory when any hash is allowed.
- Invalid hash fails.
- No body/hash match claim.
- L3 per-response claim remains partial without runtime evidence.

### Effective Nginx `add_header`

- `http`, `server`, `location`, nested location, and `if in location`.
- Standard inheritance when child has no local headers.
- One child header replaces all inherited headers under `on`.
- `add_header_inherit off`.
- `add_header_inherit merge` with local-before-inherited order matching PR #9.
- Inherited merge mode overridden deeper.
- Duplicate header names.
- Mixed casing.
- Includes at every legal context.
- Nested/glob includes preserve source and order.
- Illegal context ignored.
- HTTP/3 Alt-Svc observations and finding text remain parity-stable.

### `always` and Status Codes

- Every documented non-`always` status.
- 404 and 500 are not covered without `always`.
- `always` covers all statuses.
- CSP text containing `always` is not mistaken for the Nginx flag.
- Route requiring only 200 can pass without `always`.
- Route expecting 200 and 500 fails without `always`.
- Unknown statuses plus all-response requirement produce indeterminate unless
  `always` is present.

### Route Manifest

- HTML, API, static, download, redirect, error, internal, and custom kinds.
- Declared location, sample URI, and both.
- Exact/prefix/`^~`/regex route selection through followup-07.
- Route shadowing by regex.
- Named and internal locations only when explicitly targeted.
- Overlapping profile validation.
- Unmatched route modes.
- Rewrite/internal redirect boundary.
- Different profiles on sibling locations.
- Headers required for HTML are not automatically required for API.

### Conditional Branches

- Base scope satisfies policy, while an `if` branch drops CSP due replacement
  inheritance.
- `merge` preserves CSP in branch.
- Constant-false branch excluded only when provable.
- Dynamic branch required under `require_all`.
- Branch-local report-only header does not replace base enforcing evidence
  incorrectly.
- Separate branch evidence and source locations.

### Specialized Headers

- Referrer-Policy safe and unsafe values, including fallback list order.
- X-Content-Type-Options exact `nosniff`.
- HSTS max-age parsing, one-year minimum, includeSubDomains, and HTTPS-only
  applicability.
- COOP exact allowed values on document routes.
- Permissions-Policy conservative parser boundaries.
- X-Frame-Options cannot satisfy CSP `frame-ancestors`.
- Fixed CORS origin, wildcard, request-derived variable, and approved
  allowlist variable boundaries.
- Conflicting duplicate single-value headers.

### Findings and Assessments

- No policy emits no assessments.
- Existing rule IDs and severity remain stable.
- Every intentional no-policy correction has a named test.
- Policy failure does not add a duplicate finding.
- Existing finding IDs link through `related_rule_ids`.
- `nginx.csp_value_review` is suppressed only for explicitly assessed scopes.
- Malformed CSP finding remains even if another policy assessment passes.
- Deterministic assessment ordering and serialization.

### False-Positive Boundaries

- Report-only CSP is never enforcement.
- A CSP on one sibling location does not satisfy another.
- A server-level CSP shadowed by one local header is recognized as absent in
  that child scope.
- A header without `always` is not called absent for a 200-only route.
- An API profile is not forced to use HTML script policy.
- A static hash is not claimed to match application content.
- A dynamic nonce is not claimed fresh.
- A configured reporting endpoint is not claimed reachable.
- A stricter additional CSP is not flagged as weakening security.
- Unsupported policy intersection is indeterminate rather than guessed.

## Documentation and Coverage Effects

When implementation lands:

- `docs/rule-coverage.md` should describe the new assessment capability and
  any corrected Nginx rule semantics.
- `docs/control-source-coverage-tracker.md` should keep CIS 5.3.2/5.3.3
  `partial` by default. A later coverage decision may define an explicit
  policy-plus-runtime boundary, but that is not part of this followup.
- ASVS V3.4.3 remains `partial` because nonce freshness, hash/body matching,
  and full application source authorization are not proven statically.
- ASVS V3.4.5 and V3.4.6 should retain current full status unless the
  corrected route semantics reveal a documented counting defect; any change
  requires a separate coverage decision.
- ASVS V3.4.7 retains its configuration-visible endpoint boundary. Reporting
  delivery remains a limitation.
- ASVS V3.4.8 route-specific COOP evidence can be documented without
  automatically changing source coverage.
- `docs/benchmarks-covering.md` should explain route manifest and policy
  requirements.
- `docs/architecture.md` should document CSP AST, effective header scopes,
  conditional branches, and compatibility adapters.
- CLI/API docs should include one route/profile example and clearly state the
  no-policy behavior.
- Release notes should enumerate intentional default finding corrections.

No full-coverage percentage change is automatic.

## Acceptance Criteria

- CSP commas, semicolons, multiple header instances, dispositions, ordering,
  duplicates, and parse issues are represented correctly.
- Nonce and hash tokens are typed and safely reported.
- Report-only policy never satisfies enforcement.
- Supported multiple-policy predicates use conjunction semantics.
- Unsupported CSP intersection returns `indeterminate`.
- Effective Nginx headers support `http`, `server`, `location`,
  `if in location`, `add_header_inherit on|off|merge`, includes, and source
  evidence.
- HTTP/3 Alt-Svc behavior remains parity-stable after extraction.
- `always` is evaluated against route expected statuses.
- Route manifest prevents one-size-fits-all header assumptions.
- Policy failures are assessments, not duplicate findings.
- No-policy assessment output is empty and only enumerated semantic finding
  corrections occur.
- Exact CIS, ASVS, and OWASP rows are used.
- Coverage remains conservative and runtime limitations are explicit.
- Full test suite, generated inventory, and documentation checks pass.

## Dependencies

- Followup-03 policy loader and strict schema.
- Followup-04 assessment model and rendering.
- Followup-05 scope graph and include completeness.
- Followup-07 bounded location/URI matcher.
- PR #9 effective response-header precedent.
- Official Nginx headers module documentation.
- W3C CSP Level 3 parsing and multiple-policy model.
- Existing external runtime evidence for future nonce/hash corroboration,
  without coupling it into version 1.

## Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| CSP parser replacement causes broad cross-server regressions | Add compatibility adapters and limit semantic migration to Nginx in this PR. |
| Multiple policies are incorrectly merged | Preserve policy objects and evaluate bounded predicates over the policy set. |
| A dynamic nonce is over-credited | Pass only configuration strategy and retain explicit runtime-freshness limitation. |
| Hash presence is mistaken for body integrity proof | Never match static config hashes to bodies in version 1. |
| Location/if header overrides create a large finding delta | Enumerate allowed corrections and require named regression tests. |
| Route manifest becomes an application router | Reuse bounded selectors and concrete samples; no route discovery or rewrite execution. |
| `always` creates false all-response claims | Compare exact expected statuses and documented Nginx applicability. |
| Report-to group is accepted without a location | Require visible endpoint mapping. |
| PR becomes too large to review | Land the five implementation layers in order and avoid cross-server migration. |
| Coverage is inflated from policy configuration alone | Keep CIS/ASVS partial boundaries and require separate coverage review. |

## Rollback Plan

The implementation should be layered so rollback is possible:

1. Disable the response-header assessment evaluator and remove
   `nginx.response_headers` from policy schema.
2. Keep the shared Nginx header resolver if the HTTP/3 rule has migrated; it
   can remain as an internal refactor with parity tests.
3. Keep the CSP AST only if compatibility adapters preserve existing users;
   otherwise restore the old public helper behavior while retaining the new
   parser behind an internal API for a followup.
4. Revert migrated Nginx rule consumers individually, not the entire parser
   or scope graph.
5. Preserve PR #9 HTTP/3 behavior and all existing rule identities.
6. Revert docs describing policy assessments and corrected cases; do not
   alter conservative coverage status.

Assessments are derived output and need no data migration.

## Reviewer Checklist

- [ ] Followup-03/04/05/07 foundations are reused.
- [ ] PR #9 HTTP/3 header behavior has explicit parity tests.
- [ ] CSP parser distinguishes policy commas from directive semicolons.
- [ ] Multiple header instances and enforce/report dispositions are retained.
- [ ] Duplicate directives preserve first-directive semantics.
- [ ] Nonce/hash syntax, dynamic templates, and redacted evidence are correct.
- [ ] No runtime nonce freshness or hash/body claim is made.
- [ ] Multiple-policy predicates use sound conjunction behavior.
- [ ] Unsupported CSP intersections are indeterminate.
- [ ] Effective `add_header` covers `http`, `server`, `location`, `if`,
      includes, and `on|off|merge`.
- [ ] `always` and expected statuses are tested.
- [ ] Route manifest is bounded and response-kind aware.
- [ ] Report-only cannot satisfy enforcement.
- [ ] `report-to` requires endpoint linkage.
- [ ] X-Frame-Options does not substitute for `frame-ancestors`.
- [ ] Findings and assessments remain distinct.
- [ ] Every intentional no-policy finding correction is named and documented.
- [ ] Exact standards rows and conservative coverage notes are present.
- [ ] Cross-server migration and full CSP browser evaluation remain out of
      scope.
