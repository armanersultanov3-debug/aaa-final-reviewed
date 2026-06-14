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
- optional requests for known opt-in rule tags such as `policy-review`.

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

## Nginx reverse-proxy header policy

Schema version 1 also supports an optional top-level `nginx` section for
policy-gated analyzer semantics. The first analyzer-specific policy contract is
`nginx.reverse_proxy_headers`.

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
