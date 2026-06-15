# Audit Policy

`webconf-audit` can accept an explicit, versioned audit policy with `--policy`.
The policy is separate from suppressions, baselines, severity tuning, and
coverage accounting.

## Boundary

- A policy does not hide findings.
- A policy does not rewrite ledger coverage statuses.
- A policy does not certify a target against CIS, OWASP, ASVS, NIST, PCI DSS,
  ISO, or any other standard.
- A zero-finding run is not serialized as a control pass.
- Coverage percentages do not increase because a policy exists, validates, or
  requests an opt-in rule. Coverage changes remain downstream evidence work.

## CLI

Validate a policy file:

```bash
webconf-audit policy validate --policy .webconf-audit-policy.yml
webconf-audit policy validate --policy .webconf-audit-policy.yml --format json
```

Inspect parsed or resolved policy data:

```bash
webconf-audit policy show --policy .webconf-audit-policy.yml
webconf-audit policy show --policy .webconf-audit-policy.yml --mode local --server-type nginx --target production/edge-01
```

Apply a policy explicitly to analysis:

```bash
webconf-audit analyze-nginx nginx.conf --policy .webconf-audit-policy.yml
webconf-audit analyze-apache httpd.conf --policy .webconf-audit-policy.yml
webconf-audit analyze-lighttpd lighttpd.conf --policy .webconf-audit-policy.yml
webconf-audit analyze-iis web.config --policy .webconf-audit-policy.yml
webconf-audit analyze-external https://example.test --policy .webconf-audit-policy.yml
webconf-audit analyze-tls-inventory production-edge --policy .webconf-audit-policy.yml
```

There is no ambient policy discovery in schema version 1. If `--policy` is not
supplied, existing analyzer behavior remains unchanged.

## Schema Summary

Schema version 1 policy files contain:

- policy identity and human review provenance;
- defaults for disposition and evidence expectation;
- one or more target profiles with selectors;
- selected coverage sources and per-item overrides;
- optional requests for known opt-in rule tags such as `policy-review`;
- optional analyzer-specific contracts under bounded top-level sections such as
  `nginx.logging`, `nginx.rate_limits`, `nginx.response_headers`,
  `nginx.reverse_proxy_headers`, `nginx.sensitive_locations`, and
  `external.tls_inventories`.

YAML is loaded with bounded safe parsing. Aliases, anchors, tags, and merge
keys are rejected.

## Resolution Rules

- Exactly one profile must match the requested target.
- Local targets require `mode=local` and a concrete `server_type`.
- External targets use `mode=external`; selectors may omit `server_type` or use
  `generic`.
- Every resolved source expands to every applicable ledger item, including
  inherited defaults.
- `not-applicable` is explicit, item-specific, and requires rationale.

## Output

When a policy is supplied, JSON results include deterministic policy hashes and
the resolved profile under `result.metadata.audit_policy`.

Every analysis result, with or without a policy, also includes a versioned
`result.metadata.rule_execution` manifest describing which rules completed,
skipped, or failed. See [docs/report-format.md](report-format.md).

## Nginx logging policy

Schema version 1 also supports an optional top-level `nginx.logging` contract
for scope-aware access-log and error-log evaluation.

Minimal example:

```yaml
schema_version: 1
policy_id: nginx-logging-contract
policy_version: "2026.06"
title: Nginx logging contract
description: Policy-backed logging requirements for nginx.
defaults:
  disposition: advisory
  evidence_expectation: ledger-default
  include_unmapped_findings: true
  require_complete_execution_manifest: true
profiles:
  - profile_id: nginx-production
    title: Production nginx
    selectors:
      - mode: local
        server_type: nginx
        target_glob: "*nginx.conf"
    sources:
      - source_id: cis-nginx-3.0.0
        disposition: required
        controls: []
nginx:
  logging:
    profiles:
      - profile_id: public_server
        applies_to:
          server_names: ["www.example.test"]
          location_patterns: ["/", "/api/"]
        access:
          required: true
          allow_off: false
          conditional:
            mode: forbid
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
provenance:
  owner: Security Engineering
  approved_on: 2026-06-12
  change_ref: SEC-2026-205
```

Important boundaries:

- If the `nginx.logging` section is omitted, existing Nginx findings and
  default analysis JSON remain unchanged.
- A logging policy emits versioned per-result `control_assessments` for the
  matching analysis run only. The bounded control IDs are
  `cis-nginx-3.1.detailed-access-logging`,
  `cis-nginx-3.3.error-log-info-level`, and `policy.nginx.logging`.
- Policy results do not suppress findings. In particular, a passing logging
  assessment does not hide `nginx.missing_log_format` or any other invalid
  configuration finding.
- The generic `nginx.access_log_uses_default_format` opt-in review can be
  suppressed only where an explicit logging policy evaluates the same explicit
  format choice, to avoid duplicate operator work.
- Coverage percentages do not increase because this policy exists or because a
  scope-level assessment passes. CIS NGINX §3.1 and §3.3 remain `partial` in
  the canonical coverage tracker.

## Nginx reverse-proxy header policy

Schema version 1 also supports `nginx.reverse_proxy_headers` under the same
optional top-level `nginx` section for policy-gated analyzer semantics.

Minimal example:

```yaml
schema_version: 1
policy_id: nginx-reverse-proxy-contract
policy_version: "2026.06"
title: Nginx reverse proxy contract
description: Route-level reverse proxy header requirements.
defaults:
  disposition: advisory
  evidence_expectation: ledger-default
  include_unmapped_findings: true
  require_complete_execution_manifest: true
profiles:
  - profile_id: nginx-production
    title: Production nginx
    selectors:
      - mode: local
        server_type: nginx
        target_glob: "*nginx.conf"
    sources:
      - source_id: cis-nginx-3.0.0
        disposition: required
        controls: []
nginx:
  reverse_proxy_headers:
    profiles:
      - profile_id: public_http
        applies_to:
          upstream_families: [proxy]
          server_names: ["api.example.test"]
          location_patterns: ["/api/"]
        request_headers:
          required:
            X-Forwarded-For:
              any_of: ["$proxy_add_x_forwarded_for", "$remote_addr"]
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
          must_hide: ["X-Powered-By"]
          must_not_pass: ["Server"]
          allow_explicit_pass: []
    unmatched_routes: indeterminate
provenance:
  owner: Security Engineering
  approved_on: 2026-06-12
  change_ref: SEC-2026-204
```

Important boundaries:

- If the `nginx` section is omitted, existing Nginx findings and default
  analysis JSON remain unchanged.
- A reverse-proxy policy emits versioned per-result `control_assessments`
  records only for the matching analysis run; it does not create duplicate
  findings and does not suppress existing findings.
- Coverage percentages do not increase because this policy exists or because a
  route-level assessment passes.

## Nginx response-header policy

Schema version 1 also supports `nginx.response_headers` for route-aware CSP and
security-header contracts. The policy is optional and only emits control
assessments when it is supplied explicitly.

Minimal example:

```yaml
schema_version: 1
policy_id: nginx-response-header-contract
policy_version: "2026.06"
title: Nginx response-header contract
description: Policy-backed response-header and CSP requirements for nginx.
defaults:
  disposition: advisory
  evidence_expectation: ledger-default
  include_unmapped_findings: true
  require_complete_execution_manifest: true
profiles:
  - profile_id: nginx-production
    title: Production nginx
    selectors:
      - mode: local
        server_type: nginx
        target_glob: "*nginx.conf"
    sources:
      - source_id: cis-nginx-3.0.0
        disposition: required
        controls: []
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
        expected_statuses: [200, 404, 500]
        profile: browser-document
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
            allowed_values: [no-referrer, strict-origin-when-cross-origin]
            require_all_expected_statuses: true
          X-Content-Type-Options:
            required: true
            allowed_values: [nosniff]
            require_all_expected_statuses: true
          Cross-Origin-Opener-Policy:
            required: true
            allowed_values: [same-origin, same-origin-allow-popups]
            require_all_expected_statuses: true
          Permissions-Policy:
            required: true
            allowed_values: ["geolocation=(), camera=()"]
            require_all_expected_statuses: true
          Strict-Transport-Security:
            required_on_schemes: [https]
            min_max_age: 31536000
            include_subdomains: true
            require_all_expected_statuses: true
          X-Frame-Options:
            mode: transitional_optional
    reporting_endpoints:
      csp:
        allowed_urls: ["https://reports.example.test/csp"]
    unmatched_routes: indeterminate
    unresolved_internal_redirects: indeterminate
provenance:
  owner: Security Engineering
  approved_on: 2026-06-12
  change_ref: SEC-2026-206
```

Important boundaries:

- If the `nginx.response_headers` section is omitted, no CSP or
  response-header `control_assessments` are emitted and existing no-policy
  analyzer behavior remains in place apart from the explicitly documented
  header-semantics corrections.
- The evaluator uses effective `add_header` inheritance across `http`,
  `server`, `location`, and `if in location`, including
  `add_header_inherit on|off|merge` and `always` status applicability.
- The route manifest is explicit input. The analyzer does not crawl routes,
  infer response kinds, prove nonce freshness, match hashes to bodies, or
  execute rewrites and internal redirects.
- Report-only CSP never satisfies an enforcement requirement.
- `Permissions-Policy` is checked against the profile's explicit allowed
  values. `X-Frame-Options` is optional transitional evidence and does not
  replace the authoritative CSP `frame-ancestors` requirement.
- Policy-backed CSP/header results are assessments only. They do not suppress
  findings automatically, they do not raise coverage percentages, and they do
  not claim CIS / ASVS / NIST / PCI DSS / ISO certification.

## Nginx rate-limit policy

Schema version 1 also supports `nginx.rate_limits` for route-aware request and
connection limit contracts. The policy is optional and only emits control
assessments when it is supplied explicitly.

Minimal example:

```yaml
schema_version: 1
policy_id: nginx-rate-limit-contract
policy_version: "2026.06"
title: Nginx rate-limit contract
description: Policy-backed request and connection limit requirements for nginx.
defaults:
  disposition: advisory
  evidence_expectation: ledger-default
  include_unmapped_findings: true
  require_complete_execution_manifest: true
profiles:
  - profile_id: nginx-production
    title: Production nginx
    selectors:
      - mode: local
        server_type: nginx
        target_glob: "*nginx.conf"
    sources:
      - source_id: cis-nginx-3.0.0
        disposition: required
        controls: []
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
      - profile_id: public-api
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
          additional_zones: allow
          burst:
            min: 0
            max: 40
          delay_mode: default
          dry_run: false
          allowed_rejection_statuses: [429]
          allowed_log_levels: [notice, warn, error]
        connection:
          required: true
          accepted_zones: [api_conn_per_ip]
          require_all_zones: false
          additional_zones: allow
          connections:
            min: 1
            max: 20
          dry_run: false
          allowed_rejection_statuses: [429, 503]
          allowed_log_levels: [notice, warn, error]
    unmatched_routes: indeterminate
    unresolved_internal_redirects: indeterminate
provenance:
  owner: Security Engineering
  approved_on: 2026-06-12
  change_ref: SEC-2026-208
```

Important boundaries:

- If the `nginx.rate_limits` section is omitted, existing Nginx findings,
  fixed heuristics, opt-in review findings, and default analysis JSON remain
  unchanged.
- A rate-limit policy emits versioned per-result `control_assessments` only
  for the matching analysis run. The bounded control IDs are
  `cis-nginx-5.2.4.connections-per-ip` and
  `cis-nginx-5.2.5.requests-per-ip`.
- Policy results do not suppress findings. In particular, a passing
  rate-limit assessment does not hide `nginx.missing_limit_req`,
  `nginx.limit_req_unknown_zone`, `nginx.missing_limit_conn`, or any other
  invalid-configuration finding.
- `nginx.limit_req_zone_rate_review` and `nginx.limit_conn_zone_review`
  remain opt-in review findings when no explicit rate-limit policy applies.
  They are suppressed only for explicitly assessed subjects so the operator
  does not see duplicate policy-review work.
- Route matching reuses the bounded declared-location and sample-URI semantics
  from the Nginx route matcher. Named or internal locations are only assessed
  when the policy targets them explicitly.
- Request and connection limits are evaluated independently. A route can pass
  one control and fail or remain indeterminate for the other.
- Coverage percentages do not increase because this policy exists or because a
  route-level assessment passes. CIS NGINX §5.2.4 and §5.2.5 remain `partial`
  in the canonical coverage tracker.

## Nginx sensitive-location policy

Schema version 1 also supports `nginx.sensitive_locations` for an
operator-supplied catalog of business-sensitive routes or declared Nginx
locations and the access-control contract required for each one.

Minimal example:

```yaml
schema_version: 1
policy_id: nginx-sensitive-location-contract
policy_version: "2026.06"
title: Nginx sensitive location contract
description: Policy-backed access control requirements for sensitive nginx routes.
defaults:
  disposition: advisory
  evidence_expectation: ledger-default
  include_unmapped_findings: true
  require_complete_execution_manifest: true
profiles:
  - profile_id: nginx-production
    title: Production nginx
    selectors:
      - mode: local
        server_type: nginx
        target_glob: "*nginx.conf"
    sources:
      - source_id: cis-nginx-3.0.0
        disposition: required
        controls: []
nginx:
  sensitive_locations:
    catalog:
      - entry_id: admin-console
        kind: admin
        server_names: ["example.test"]
        declared_location:
          modifier: prefix_no_regex
          pattern: /admin/
        sample_uris: ["/admin/"]
        exposure: external
        required_controls:
          all_of:
            - ip_allowlist:
                allowed_cidrs: ["10.20.0.0/16"]
                require_deny_all_fallback: true
            - auth_request: {}
          satisfy: all
      - entry_id: metrics
        kind: monitoring
        server_names: ["example.test"]
        sample_uris: ["/metrics"]
        exposure: internal_only
        required_controls:
          one_of:
            - internal: {}
            - deny_all: {}
    unmatched_entries: indeterminate
    allow_unresolved_internal_redirects: false
provenance:
  owner: Security Engineering
  approved_on: 2026-06-12
  change_ref: SEC-2026-206
```

Important boundaries:

- If the `nginx.sensitive_locations` section is omitted, existing Nginx
  findings, baseline sensitive-path rules, and default analysis JSON remain
  unchanged.
- A sensitive-location policy emits versioned per-result
  `control_assessments` only for the matching analysis run. The bounded
  control IDs are `policy.nginx.sensitive-location.<entry_id>`,
  `cis-nginx-5.1.1.sensitive-ip-filters`, and
  `asvs-5.0.0-v13.4.5.sensitive-endpoint-exposure`.
- Policy results do not suppress findings. In particular, a passing
  sensitive-location assessment does not hide
  `nginx.missing_access_restrictions_on_sensitive_locations`,
  `nginx.sensitive_location_missing_ip_filter`, or any other invalid
  configuration finding.
- If routing, includes, optional auth-module visibility, dynamic address
  rules, or unresolved internal redirects prevent a sound conclusion, the
  assessment becomes `indeterminate` rather than an assumed `pass`.
- Coverage percentages do not increase because this policy exists or because a
  route-level assessment passes. CIS NGINX В§5.1.1 remains `partial` in the
  canonical coverage tracker.

## External TLS inventory policy

Schema version 1 also supports `external.tls_inventories` for declared
endpoint and SNI inventories. This workflow is separate from
`analyze-external`: it does not discover scope from DNS, SANs, redirects, or
port scans, and it does not treat one handshake as deployment-wide proof.

Minimal example:

```yaml
schema_version: 1
policy_id: external-tls-inventory
policy_version: "2026.06"
title: External TLS inventory
description: Declared endpoint and SNI inventory for bounded TLS assessment.
defaults:
  disposition: advisory
  evidence_expectation: ledger-default
  include_unmapped_findings: true
  require_complete_execution_manifest: true
profiles:
  - profile_id: production-edge
    title: Production edge inventory
    selectors:
      - mode: external
        target_glob: "tls-inventory/*"
    sources:
      - source_id: cis-nginx-3.0.0
        disposition: required
external:
  tls_inventories:
    - id: production-edge
      environment: production
      declared_complete: true
      completeness_attestation:
        asserted_by: platform-team
        asserted_at: "2026-06-12T08:00:00Z"
        basis: load-balancer-listener-export
      trust:
        mode: system
      required_evidence:
        - handshake
        - certificate_name
        - certificate_chain
        - protocol_support
        - negotiated_cipher
        - ocsp_stapling
      entries:
        - id: api-primary
          connect_host: 203.0.113.10
          connect_port: 443
          sni_name: api.example.test
          http_host: api.example.test
          path: /
          expected_certificate_names:
            - api.example.test
provenance:
  owner: Security Engineering
  approved_on: 2026-06-15
  change_ref: SEC-2026-210
```

Run it with:

```bash
webconf-audit analyze-tls-inventory production-edge --policy .webconf-audit-policy.yml
webconf-audit analyze-tls-inventory production-edge --policy .webconf-audit-policy.yml --format json > tls-inventory-analysis.json
webconf-audit assess --report tls-inventory-analysis.json --fail-on fail,indeterminate
```

Important boundaries:

- `connect_host`, `sni_name`, `http_host`, and `expected_certificate_names`
  are distinct fields. Evidence from one entry is never joined to another.
- `declared_complete` is operator-declared completeness. The analyzer does not
  infer completeness from DNS, SANs, redirects, or port discovery.
- A positive run is bounded TLS observation and scanner-evidence coverage
  within the declared endpoint/SNI inventory only.
- Missing mandatory observations, missing completeness attestation, probe
  failures, or unsupported bounded observations produce `indeterminate`, not
  an inferred `pass`.
- Existing TLS findings remain independently visible. A control assessment does
  not suppress `Finding` records.
- This workflow does not claim full revocation validation or certification
  against CIS, OWASP ASVS, NIST SP 800-52 Rev. 2, PCI DSS, or ISO/IEC 27002.

## Assessment interaction

`assess` does not silently load a new policy. It trusts the embedded resolved
policy from the analysis report and uses any supplied `--policy` file only for
verification.

Example:

```bash
webconf-audit analyze-nginx nginx.conf --policy .webconf-audit-policy.yml --format json > analysis.json
webconf-audit assess --report analysis.json --policy .webconf-audit-policy.yml
```

Verification succeeds only when the supplied policy resolves to the same
`policy_id`, `policy_version`, `raw_sha256`, and `resolved_sha256` that were
embedded at analysis time.

Policy dispositions affect assessment conservatively:

- `required` can become `fail`, `partial`, `pass`, `indeterminate`, or
  `not-assessed`
- `advisory` uses the same evidence model and can still be rendered with the
  same per-control assessment statuses, but the disposition itself does not
  change how the engine derives `pass` or `fail`; it remains additive context
  and does not change source coverage totals
- `review` yields `review` unless direct negative evidence produces `fail` or
  incomplete execution produces `indeterminate`
- `not-applicable` keeps the control out of in-scope target conclusions, but
  mapped findings are retained as out-of-policy context rather than deleted

Example: the same `control-pass` evidence can render a control `pass` under
both `required` and `advisory`; the difference is policy intent and coverage
accounting, not a different status algorithm. Neither disposition changes the
canonical ledger numerators during assessment. See
[docs/control-assessment.md](control-assessment.md) for the status rules.

Policies remain separate from:

- suppressions
- baselines
- severity
- coverage accounting
- assessment status gating
