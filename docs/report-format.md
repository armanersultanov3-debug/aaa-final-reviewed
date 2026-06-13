# Report Format

`webconf-audit` now publishes two separate machine-readable artifacts:

- the analysis finding report from `analyze-*`
- the control assessment report from `assess`

They are intentionally separate. Findings, technical analysis issues, policy
resolution, suppressions, and control assessment are different layers.

## Analysis JSON

Schema version 1 analysis reports include top-level provenance:

```json
{
  "schema_version": 1,
  "generator": {
    "package_name": "webconf-audit",
    "package_version": "0.1.0",
    "registry_revision": "sha256:..."
  }
}
```

The existing payload shape remains additive. The top level still carries:

- `generated_at`
- `summary`
- `results`
- `findings`
- `finding_groups`
- `new_findings`
- `resolved_findings`
- `unchanged_findings`
- `suppressed_findings`
- `standards`
- `issues`

Each result keeps its full finding and issue payloads and now also carries:

- `result.metadata.audit_policy`
- `result.metadata.rule_execution`

### Required metadata for assessment

`assess` accepts only schema version 1 analysis reports that include:

- stable finding `fingerprint` values
- complete standards mappings on findings, including `coverage`, `origin`, and
  any `derived_from` provenance
- embedded resolved policy metadata
- embedded versioned rule execution manifest
- generator registry revision

Legacy analysis JSON without this metadata remains viewable through the normal
report tooling, but it is rejected for control assessment.

## Finding fingerprints

Fingerprints are report-local SHA-256 identifiers for a finding location and
rule result. They are stable enough for suppressions, baselines, and
assessment evidence references, but they are not list indexes.

Assessment references findings by fingerprint only. It does not copy raw
response bodies, request headers, cookies, filesystem secrets, or other
secret-bearing evidence into the assessment artifact.

## Rule execution manifest

Every result includes a versioned terminal-state manifest:

```json
{
  "schema_version": 1,
  "registry_revision": "sha256:...",
  "selected_rule_ids": ["..."],
  "completed_rule_ids": ["..."],
  "skipped_rules": [{"rule_id": "...", "reason": "..."}],
  "failed_rules": [{"rule_id": "...", "issue_code": "...", "stage": "..."}]
}
```

Skip reasons in schema version 1 are:

- `mode-incompatible`
- `server-incompatible`
- `input-unavailable`
- `opt-in-not-selected`
- `prerequisite-failed`

Absence of a finding does not prove that a rule completed. Assessment uses the
manifest to distinguish completed, skipped, failed, and not-selected evidence.

## Assessment JSON

Assessment has its own schema version and does not replace the analysis
report.

Top-level fields:

- `schema_version`
- `report_id`
- `generated_at`
- `generator`
- `inputs`
- `targets`
- `sources`
- `summary`
- `issues`

Important semantics:

- `coverage_summary` under each source is copied from the canonical ledger
  snapshot; it is not recalculated from target results.
- every resolved policy control gets exactly one assessment status
- `pass` requires explicit direct pass semantics; a no-finding default does not
  imply pass
- suppressed direct findings remain failures and retain suppression provenance
- no compliance percentage is emitted

## Determinism

Both JSON renderers are deterministic in key ordering and semantic list
ordering. The only intentionally time-varying field in repeated runs with the
same inputs is `generated_at`; the assessment `report_id` is derived from input
hashes and therefore remains stable for identical trusted inputs.
