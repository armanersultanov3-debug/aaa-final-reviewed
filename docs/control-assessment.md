# Control Assessment

`webconf-audit assess` builds a conservative target-assessment artifact from:

1. a schema-versioned analysis JSON report
2. the canonical coverage ledger, or an explicitly supplied validated ledger
3. the embedded resolved audit policy
4. the embedded rule execution manifest
5. the live rule registry in the running package

Assessment is separate from the normal finding report and separate from global
source coverage percentages.

## Trust boundary

The command does not re-run analyzers, re-open scanned configuration files, or
re-probe endpoints. It evaluates only the trusted inputs recorded above.

The optional `--policy` argument is verification-only. It must resolve to the
same embedded policy hashes that were captured at analysis time.

Some analyzers can also embed versioned route- or scope-level
`control_assessments` inside the analysis JSON when an explicit policy enables
that feature. These records are trusted as additional structured evidence, but
they do not replace the separate assessment artifact or its conservative status
aggregation rules.

Current analyzer-native examples include the Nginx reverse-proxy header
contract, the Nginx logging contract, and the Nginx sensitive-location
contract. These scope-level records may say `pass`, `fail`,
`not-applicable`, or `indeterminate` for the declared contract, but they do
not rewrite finding severity, suppressions, baselines, or source coverage
totals.

## Statuses

Schema version 1 uses these statuses:

- `pass` - explicit declared direct pass semantics completed with no
  contradictory evidence
- `fail` - direct negative evidence shows the control is not met
- `partial` - only partial, facet-level, or materially incomplete evidence is
  available
- `review` - operator judgment is required
- `indeterminate` - execution failures, skips, conflicts, or missing required
  evidence prevent a reliable conclusion
- `not-assessed` - no applicable evidence path completed for the control
- `not-applicable` - the resolved policy explicitly marked the control out of
  scope

`pass` is intentionally rare. A zero-finding run does not become `pass` unless
the ledger explicitly assigns pass semantics to the completed evidence.

## Absence semantics

Assessment extends ledger evidence with versioned absence semantics:

- `none` - no finding gives no positive conclusion
- `facet-pass` - no finding supports only named facets and normally still leads
  to `partial`
- `control-pass` - no finding may support `pass`, but only for explicit
  declared direct evidence reviewed in the ledger

Default migrated evidence uses `none`.

Required-rule skips are mapped conservatively from the embedded execution
manifest:

- `mode-incompatible` becomes missing evidence with reason
  `mode-unavailable`, which yields `indeterminate`
- `server-incompatible` becomes missing evidence with reason
  `server-unavailable`, which yields `indeterminate`
- `input-unavailable`, `opt-in-not-selected`, and `prerequisite-failed` are
  normalized to missing evidence reason `skipped`, which yields
  `indeterminate`
- a required rule omitted from `selected_rule_ids` entirely becomes
  `not-selected`; if no other positive or negative path exists, the control
  remains `not-assessed`
- a completed required rule with `absence_semantics=none` adds
  `no-pass-semantics`; this remains `not-assessed`, not `indeterminate`

## Status precedence

For applicable controls, the engine resolves conflicts conservatively:

1. `fail`
2. `indeterminate`
3. `review`
4. `partial`
5. `pass`
6. `not-assessed`

`not-applicable` is a separate explicit policy decision evaluated first. When a
control is not applicable, mapped findings are still retained as out-of-policy
context and are not silently suppressed.

## Examples

- A suppressed direct finding still yields `fail`.
- A completed rule with `absence_semantics=none` and no finding yields
  `not-assessed`, not `pass`.
- A single required rule skipped with `opt-in-not-selected` yields
  `indeterminate`, because the required evidence path did not complete.
- A `policy-review` ledger item or `review` policy disposition yields `review`
  unless execution was incomplete.
- A skipped required rule yields `indeterminate`.
- An uncovered ledger control yields `not-assessed` with explicit missing
  evidence.

## CLI

```bash
webconf-audit assess --report analysis.json
webconf-audit assess --report analysis.json --format json
webconf-audit assess --report analysis.json --source owasp-asvs-5.0.0
webconf-audit assess --report analysis.json --policy .webconf-audit-policy.yml
webconf-audit assess --report analysis.json --output assessment.json
webconf-audit assess --report analysis.json --fail-on fail,indeterminate
```

Exit codes:

- `0` - assessment produced and no requested gate status was present
- `1` - report, ledger, policy verification, registry, or output handling
  failed trust checks
- `2` - invalid CLI usage
- `3` - assessment produced successfully and a requested `--fail-on` status was
  present

`--fail-on` is opt-in. There is no default compliance gate.

## Important boundaries

- Assessment does not change ledger coverage totals.
- Assessment does not certify CIS, OWASP, ASVS, NIST, PCI DSS, ISO, or any
  other source.
- A target `pass` does not increase a global coverage numerator.
- A target `fail` does not decrease a global coverage numerator.
- Findings, suppressions, baselines, policy review, and assessment remain
  separate mechanisms.
