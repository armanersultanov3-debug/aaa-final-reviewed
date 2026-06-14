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
  `nginx.logging`, `nginx.reverse_proxy_headers`, and
  `nginx.sensitive_locations`.

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
