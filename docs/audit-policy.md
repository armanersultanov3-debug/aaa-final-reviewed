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
