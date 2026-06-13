# Report Format

`webconf-audit` supports text and JSON output. The JSON format is additive:
existing consumers that ignore unknown keys can continue to parse older fields.

## JSON Envelope

The top-level JSON report contains the generated summary plus one or more
`results`. Each result keeps its existing finding and issue payloads and now
adds policy-aware metadata in `result.metadata`.

## `audit_policy`

`result.metadata.audit_policy` is:

- `null` when no explicit policy was supplied;
- a resolved schema-versioned policy payload when `--policy` was supplied and
  resolved successfully.

The resolved payload includes:

- `schema_version`
- `policy_id`
- `policy_version`
- `profile_id`
- `raw_sha256`
- `resolved_sha256`
- resolved target identity
- requested opt-in tags
- fully expanded source and control entries

## `rule_execution`

Every result includes:

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

Skip reasons are versioned and currently include:

- `mode-incompatible`
- `server-incompatible`
- `input-unavailable`
- `opt-in-not-selected`
- `prerequisite-failed`

## Important Semantics

- A completed rule with no finding is not serialized as `pass`.
- Absence of findings does not imply that a declared control passed.
- Technical analysis problems stay in `issues`.
- Findings remain visible even when a policy later marks a control as review or
  not applicable.
- A missing or untrustworthy execution manifest is treated as a fatal analysis
  problem rather than emitted as incomplete metadata.
