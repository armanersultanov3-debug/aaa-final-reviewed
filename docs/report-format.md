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
    "package_version": "0.1.2",
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
- optional `result.control_assessments`

`result.control_assessments` is reserved for analyzer-native, policy-gated
assessment records. In schema version 1 it is emitted only when a compatible
analyzer can evaluate an explicit contract such as the Nginx logging,
rate-limit, reverse-proxy header, or sensitive-location policies. The field is
absent by default when no such policy section is supplied.

Each `control_assessments` entry is independently versioned and currently
contains:

- `schema_version`
- `control_id`
- `title`
- `status`
- `scope`
- `summary`
- `evidence`
- `related_rule_ids`
- `policy_source`
- `metadata`

For `nginx.logging`, `metadata` carries the scope-aware contract details used by
the analyzer, including `policy_section`, `profile_id`, `server_scope_id`,
`logging_scope_id`, `logging_kind`, effective destinations, resolved format
definitions, required/present/missing field groups, and any
`indeterminate_reasons` or runtime-dependence notes.

For `nginx.rate_limits`, `metadata` carries the route-scoped contract details
used by the analyzer, including `policy_section`, `profile_id`,
`server_scope_id`, `route_scope_id`, `route_label`, `server_names`, effective
request and connection limit lists, referenced zone definitions, effective
dry-run / status / log-level values, the route completeness flag, any
`indeterminate_reasons`, any `failures`, and relevant `unsupported_evidence`.

For `nginx.sensitive_locations`, `metadata` carries the catalog-scoped contract
details used by the analyzer, including `policy_section`, `catalog_entry_id`,
`server_scope_id`, declared location selector data, `sample_uris`,
`effective_satisfy`, `protection_classification`, effective ordered
`allow` / `deny` rules, `shadowed_samples`, and any
`indeterminate_reasons` or coverage-boundary notes.

### Required metadata for assessment

`assess` accepts only schema version 1 analysis reports that include:

- stable finding `fingerprint` values
- complete standards mappings on findings, including `coverage`, `origin`, and
  any `derived_from` provenance
- embedded resolved policy metadata under `result.metadata.audit_policy`,
  including `policy_id`, `policy_version`, `raw_sha256`, and
  `resolved_sha256`
- embedded versioned rule execution manifest
- generator registry revision

`raw_sha256` and `resolved_sha256` are lowercase 64-character SHA-256 hex
digests. When `assess --policy ...` is supplied, the policy is re-resolved
against the assessment ledger and those hashes are compared with the embedded
metadata. See [docs/audit-policy.md](audit-policy.md) for the full policy
schema.

Legacy analysis JSON without this metadata remains viewable through the normal
report tooling, but it is rejected for control assessment.

When present, analyzer-native `result.control_assessments` are preserved as
analysis evidence. They do not replace the separate `assess` artifact, which
still owns cross-target aggregation, ledger application, and final target
status reporting.

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

- `coverage_summary` under each source is copied from the ledger used at
  assessment time: the packaged canonical ledger by default, or the explicitly
  supplied `assess --ledger ...` file. It is not recalculated from target
  results.
- only sources that are present in the resolved target assessment are emitted,
  and each emitted source carries the full copied summary for that source from
  the assessment ledger
- if the ledger changes between `analyze-*` and `assess`, assessment uses the
  current ledger input and verifies that the embedded resolved policy still
  points at valid `source_id` and `item_id` entries; mismatches fail trust
  checks instead of silently re-scoring coverage
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
