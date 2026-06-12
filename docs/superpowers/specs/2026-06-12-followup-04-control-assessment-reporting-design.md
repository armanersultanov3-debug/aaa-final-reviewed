# Control Assessment Reporting Design

Date: 2026-06-12
Status: proposed
Sequence: follow-up 04 of 14

## Inherited State After PR #8 and PR #9

This design starts from `master` commit
`1e1cbbb7209a199282b28f823a0a7b07cc7df0bc` and depends on the preceding
follow-ups:

1. follow-up 01 corrects crosswalk integrity and records declared versus
   derived mapping provenance;
2. follow-up 02 makes the coverage ledger machine-readable and gives every
   source and counted item a stable ID;
3. follow-up 03 defines explicit audit policy, resolved applicability, and a
   complete per-rule execution manifest.

PR #8 and PR #9 describe product-level source coverage. They do not assess a
specific web server or endpoint. The current analyzers emit findings and
analysis issues, and reporting groups findings by standard references, but
grouping is not a control conclusion.

The inherited distinctions remain binding:

- `full`, `partial`, `policy-review`, `uncovered`, and `excluded` are ledger
  coverage states;
- rule category and severity are not coverage;
- standard-reference strength is not a target result;
- an opt-in policy-review rule is not an automated compliance check;
- absence of a finding is not proof that the rule ran or that the control
  passed.

The known drift corrected by follow-up 01 must remain visible in assessment:

- ASVS cookie findings must attach to the corrected `3.3.x` requirements;
- CORS `3.4.2` and COOP `3.4.8` must use real registry-backed references;
- ASVS `3.4.7` cannot report a full-control pass from partial CSP reporting
  checks;
- OWASP Top 10:2025 derived mappings cannot independently prove a direct
  category outcome;
- PCI assessments must use the corrected requirement wording and must not
  revive the unsupported combined `8.3.5 / 8.3.6` claim.

## Problem

Users can currently see findings and source mapping labels, but they cannot
obtain a conservative, machine-readable answer to:

- which policy controls were assessed;
- what checks actually ran;
- which findings support a negative conclusion;
- where only partial evidence exists;
- which controls require human review;
- which controls could not be assessed due to errors or missing evidence;
- which controls were explicitly not applicable;
- how the conclusion relates to product-level coverage.

A naive report would map "finding present" to fail and "no finding" to pass.
That is unsafe. Rules may be partial, related, derived, skipped, unable to
observe the complete requirement, or designed only to raise selected negative
signals.

The project needs a separate control assessment artifact with explicit evidence
semantics and conservative status calculation.

## Goals

1. Produce a versioned control assessment report from an existing analysis
   report, canonical ledger, and resolved audit policy.
2. Keep target assessment separate from global source coverage.
3. Preserve mapping strength and origin on every evidence link.
4. Use the execution manifest to distinguish completed checks from skipped or
   failed checks.
5. Define conservative, deterministic status precedence.
6. Never infer pass solely from no findings.
7. Keep suppressed findings visible in assessment evidence.
8. Support stable JSON and readable text output.
9. Record hashes and revisions needed to reproduce the assessment inputs.
10. Provide automation-friendly exit behavior without calling the artifact a
    compliance certificate.

## Non-Goals

- Certifying compliance with any source.
- Replacing auditor judgment or evidence outside the product.
- Modifying analyzer findings, suppressions, registry mappings, or the ledger.
- Fetching external standards, tickets, or evidence.
- Combining analysis and assessment into one opaque command in schema version
  1.
- Generating HTML, PDF, SARIF, or signed attestations in the initial design.
- Treating related or derived mappings as direct proof.
- Automatically waiving a failed control because its finding was suppressed.
- Calculating global coverage from target assessment results.

## Exact Sources in Scope

Assessment schema version 1 reports controls only for the exact source editions
carried by the canonical follow-up 02 ledger:

| Source ID | Edition | Authority |
| --- | --- | --- |
| `cis-nginx-3.0.0` | CIS NGINX Benchmark v3.0.0 | `https://www.cisecurity.org/benchmark/nginx` |
| `cis-apache-http-server-2.4-2.3.0` | CIS Apache HTTP Server 2.4 Benchmark v2.3.0 | `https://www.cisecurity.org/benchmark/apache_http_server` |
| `cis-microsoft-iis-10-1.2.1` | CIS Microsoft IIS 10 Benchmark v1.2.1 | `https://www.cisecurity.org/benchmark/microsoft_iis` |
| `owasp-top10-2025` | OWASP Top 10:2025 | `https://owasp.org/Top10/2025/` |
| `owasp-asvs-5.0.0` | OWASP ASVS 5.0.0 selected web/frontend requirements | `https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md` |
| `nist-sp-800-52r2` | NIST SP 800-52 Rev. 2 selected requirements | `https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final` |
| `pci-dss-4.0.1` | PCI DSS v4.0.1 selected requirements | `https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf` |
| `iso-iec-27002-2022` | ISO/IEC 27002:2022 selected controls | `https://www.iso.org/standard/75652.html` |

The assessment renderer uses the ledger's project-authored titles and
references. It does not embed licensed requirement text or fetch any authority
URL. Reports for a future source edition require a validated ledger snapshot
that names that edition explicitly.

## Inputs and Trust Boundaries

The assessment consumes:

1. an analysis report in the project's versioned JSON format;
2. the packaged canonical coverage ledger, or an explicitly supplied validated
   local ledger;
3. the resolved audit policy embedded in the analysis report;
4. the complete rule execution manifest embedded in the analysis report;
5. the live rule registry corresponding to the running package.

The assessment command does not silently load a new policy file. The resolved
policy embedded during analysis is authoritative for that report. An optional
`--policy` argument may be offered only as a verification input: its canonical
resolved hash must exactly match the embedded policy or assessment fails.

This prevents a report from being reinterpreted later under a different policy
without re-analysis.

## Assessment Status Model

```python
AssessmentStatus = Literal[
    "pass",
    "fail",
    "partial",
    "review",
    "indeterminate",
    "not-assessed",
    "not-applicable",
]
```

Meanings:

| Status | Meaning |
| --- | --- |
| `pass` | All policy-required evidence with explicit pass semantics completed, no contradictory evidence exists, and the ledger permits the conclusion |
| `fail` | Declared direct evidence proves the required control condition is not met within assessed scope |
| `partial` | Evidence proves only a facet, uses partial mapping, or leaves a material portion of the requirement unassessed |
| `review` | Operator judgment is required, including policy-review controls and evidence that has no automated pass/fail semantics |
| `indeterminate` | Execution errors, conflicts, malformed input, or missing required evidence prevent a reliable conclusion |
| `not-assessed` | No applicable evidence was selected or executed for the control |
| `not-applicable` | The resolved policy explicitly marks the control not applicable with rationale |

`pass` is intentionally difficult to reach. A completed negative-signal rule
with no finding does not automatically have pass semantics.

## Evidence Semantics

The ledger evidence relation is extended additively for assessment:

```python
AbsenceSemantics = Literal[
    "none",
    "facet-pass",
    "control-pass",
]
```

```python
class AssessableRuleEvidence(BaseModel):
    rule_id: str
    strength: Literal["direct", "partial", "related"]
    origin: Literal["declared", "derived"]
    absence_semantics: AbsenceSemantics = "none"
    assessed_facets: tuple[str, ...] = ()
```

Rules:

- `none`: no finding yields no positive conclusion;
- `facet-pass`: completed with no finding supports only named facets and
  normally results in `partial` unless every required facet is independently
  satisfied;
- `control-pass`: completed with no finding may support `pass`, but only for a
  declared direct mapping, explicit complete scope, and policy-required
  evidence set;
- related or derived evidence always has `absence_semantics == "none"`;
- policy-review rules always have `absence_semantics == "none"`;
- the default for all migrated evidence is `none`;
- assigning `facet-pass` or `control-pass` is a separate evidence-bearing
  ledger change and cannot be inferred by the assessment engine.

Therefore, initial rollout may produce few or no `pass` results. That is
correct until rule contracts are reviewed.

## Data Model

### Root Report

```python
class ControlAssessmentReport(BaseModel):
    schema_version: Literal[1]
    report_id: str
    generated_at: datetime
    generator: GeneratorIdentity
    inputs: AssessmentInputs
    targets: tuple[AssessmentTarget, ...]
    sources: tuple[SourceAssessment, ...]
    summary: AssessmentSummary
    issues: tuple[AssessmentIssue, ...]
```

```python
class GeneratorIdentity(BaseModel):
    package_name: str
    package_version: str
    registry_revision: str
```

### Input Provenance

```python
class AssessmentInputs(BaseModel):
    analysis_report_sha256: str
    analysis_report_schema_version: int
    ledger_snapshot_id: str
    ledger_sha256: str
    policy_id: str
    policy_version: str
    policy_raw_sha256: str
    policy_resolved_sha256: str
    execution_manifest_schema_version: int
```

All hashes are lowercase SHA-256 hex strings. The analysis report hash is
computed over the input bytes; the ledger hash is computed over deterministic
canonical JSON.

### Target

```python
class AssessmentTarget(BaseModel):
    target_id: str
    display_name: str
    mode: Literal["local", "external"]
    server_type: str | None
```

The report does not include raw configuration, credentials, request headers,
response bodies, or secret-bearing URLs.

### Source and Control

```python
class SourceAssessment(BaseModel):
    source_id: str
    title: str
    version: str
    coverage_summary: CoverageSummaryReference
    controls: tuple[ControlAssessment, ...]
    summary: AssessmentSummary
```

```python
class CoverageSummaryReference(BaseModel):
    applicable: int
    full: int
    partial: int
    policy_review: int
    uncovered: int
    full_percent: Decimal
```

This is a copied reference to the ledger snapshot, clearly labeled
`coverage_summary`; it is never recalculated from assessments.

```python
class ControlAssessment(BaseModel):
    source_id: str
    item_id: str
    title: str
    references: tuple[ControlReference, ...]
    ledger_status: CoverageStatus
    policy_disposition: ControlDisposition
    status: AssessmentStatus
    rationale: str
    evidence: tuple[AssessmentEvidence, ...]
    missing_evidence: tuple[MissingEvidence, ...]
    issues: tuple[str, ...]
```

### Evidence

```python
class AssessmentEvidence(BaseModel):
    rule_id: str
    target_id: str
    mapping_strength: Literal["direct", "partial", "related"]
    mapping_origin: Literal["declared", "derived"]
    absence_semantics: AbsenceSemantics
    execution_state: Literal["completed", "skipped", "failed"]
    finding_ids: tuple[str, ...]
    finding_severities: tuple[str, ...]
    suppressed: bool
    suppression_refs: tuple[str, ...]
    observed_facets: tuple[str, ...]
    note: str
```

```python
class MissingEvidence(BaseModel):
    rule_id: str | None
    expectation: EvidenceExpectation
    reason: Literal[
        "not-selected",
        "skipped",
        "execution-failed",
        "mode-unavailable",
        "server-unavailable",
        "ledger-uncovered",
        "no-pass-semantics",
        "operator-evidence-required",
    ]
    detail: str
```

Finding IDs are stable report-local fingerprints, not list indexes.

### Summary

```python
class AssessmentSummary(BaseModel):
    total: NonNegativeInt
    passed: NonNegativeInt
    failed: NonNegativeInt
    partial: NonNegativeInt
    review: NonNegativeInt
    indeterminate: NonNegativeInt
    not_assessed: NonNegativeInt
    not_applicable: NonNegativeInt
```

Invariant:

```text
total = passed + failed + partial + review
      + indeterminate + not_assessed + not_applicable
```

No "compliance percentage" is calculated. The status distribution is not
converted into a score.

## Deterministic Assessment Algorithm

The engine evaluates each resolved policy control independently.

### Step 1: Applicability

- explicit `not-applicable` produces `not-applicable`;
- the policy rationale is copied;
- analyzer findings mapped to that control remain in a separate
  out-of-policy evidence section or report issue and are not deleted.

### Step 2: Ledger Capability

- ledger `uncovered` with required disposition produces `not-assessed` and
  `ledger-uncovered` missing evidence;
- ledger `policy-review` produces at least `review`;
- ledger `partial` caps an otherwise positive automated conclusion at
  `partial` unless the policy supplies separately modeled operator evidence in
  a future schema;
- ledger `full` permits, but does not guarantee, `pass`.

### Step 3: Execution Completeness

- missing manifest or hash mismatch is a report-level fatal error;
- required rule failed or was skipped produces `indeterminate`, unless no rule
  was selected at all, which produces `not-assessed`;
- unrelated analyzer issues do not taint every control;
- target-wide parse or probe failure makes every dependent control
  `indeterminate`.

### Step 4: Negative Evidence

- an unsuppressed finding with declared direct mapping produces `fail`;
- a finding with partial mapping produces at least `partial`;
- a finding with related or derived mapping is supporting context and cannot
  independently produce `fail`;
- a suppressed direct finding remains `fail`; suppression provenance is
  recorded as workflow context and never changes the observed control state;
- finding severity affects prioritization and display, not whether the mapped
  control evidence exists.

### Step 5: Positive Evidence

- completed rules with `absence_semantics == "none"` add execution evidence but
  no positive status;
- completed `facet-pass` rules satisfy only their named facets;
- all policy-required facets must be covered without contradictory findings;
- `control-pass` is considered only for declared direct mappings;
- `pass` requires every policy-required rule to complete, every required facet
  to be satisfied, no direct negative evidence, no unresolved issue, ledger
  status `full`, and policy disposition `required` or `advisory`;
- a derived OWASP 2025 mapping cannot satisfy this condition.

### Step 6: Review and Conservative Fallback

- policy disposition `review` yields `review` unless direct negative evidence
  produces `fail` or execution failure produces `indeterminate`;
- incomplete facet evidence yields `partial`;
- no completed relevant evidence yields `not-assessed`;
- conflicting evidence or unclassified failure yields `indeterminate`;
- there is no fallback from uncertainty to pass.

## Status Precedence

When multiple conditions apply, use:

```text
not-applicable
fatal input error (no report emitted)
fail
indeterminate
review
partial
pass
not-assessed
```

`not-applicable` is evaluated first because it is an explicit policy scope
decision, but mapped findings are still retained outside the concluded scope.
Within applicable controls, verified direct negative evidence outranks an
execution error because the negative fact remains established. The error is
also retained as an issue.

## Analysis Report Requirements

The input JSON format must provide:

- stable report schema version;
- target identity and mode;
- findings with stable IDs;
- finding rule IDs;
- complete primary and secondary standard mappings, including origin;
- suppression state and suppression reference;
- analysis issues with affected stage/rule/target;
- resolved audit policy;
- rule execution manifest;
- package and registry revision.

Assessment refuses legacy reports that lack policy or execution metadata.
Users can still view those reports with existing tooling; they cannot be
retrofitted into trustworthy assessments.

## Application API

```python
def load_analysis_report(path: Path) -> AnalysisReport: ...

def verify_assessment_inputs(
    report: AnalysisReport,
    ledger: CoverageLedger,
    registry: RuleRegistry,
    verification_policy: AuditPolicy | None = None,
) -> tuple[AssessmentIssue, ...]: ...

def build_control_assessment(
    report: AnalysisReport,
    ledger: CoverageLedger,
    registry: RuleRegistry,
) -> ControlAssessmentReport: ...

def render_assessment_text(
    assessment: ControlAssessmentReport,
) -> str: ...

def render_assessment_json(
    assessment: ControlAssessmentReport,
) -> str: ...
```

```python
class AssessmentIssue(BaseModel):
    code: str
    severity: Literal["error", "warning"]
    message: str
    source_id: str | None = None
    item_id: str | None = None
    rule_id: str | None = None
    target_id: str | None = None
```

Assessment building is pure with respect to its parsed inputs. It performs no
analysis, probing, or policy resolution.

## CLI Design

```text
webconf-audit assess --report analysis.json
webconf-audit assess --report analysis.json --format json
webconf-audit assess --report analysis.json --source owasp-asvs-5.0.0
webconf-audit assess --report analysis.json --policy .webconf-audit-policy.yml
webconf-audit assess --report analysis.json --output assessment.json
webconf-audit assess --report analysis.json --fail-on fail,indeterminate
```

Options:

| Option | Behavior |
| --- | --- |
| `--report PATH` | Required versioned analysis JSON |
| `--ledger PATH` | Optional local ledger, validated and hash-recorded |
| `--policy PATH` | Optional verification only; must match embedded resolved policy |
| `--source ID` | Repeatable display/output filter; does not change assessment calculation |
| `--format text\|json` | Output representation |
| `--output PATH` | Atomic output file; stdout when omitted |
| `--fail-on LIST` | Comma-separated assessment statuses that trigger gate failure |
| `--force` | Permit replacement of an existing output file |

Default `--fail-on` is empty. The command reports facts without imposing an
organization gate unless explicitly requested.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Assessment produced and gate condition not met |
| `1` | Input, schema, hash, registry, ledger, policy, or write failure |
| `2` | Invalid CLI usage |
| `3` | Assessment produced successfully and a requested `--fail-on` status exists |

When exit `3` is used, the report is still written completely.

## Text Report Design

Text output is answer-first but conservative:

1. input provenance and policy identity;
2. status summary by source;
3. controls ordered by status severity, then source and item ID;
4. evidence and missing evidence for each non-pass status;
5. explicit source coverage context;
6. warnings that assessment is not certification.

The report must use separate labels:

```text
Product source coverage: partial
Target assessment: indeterminate
```

It must never render a combined phrase such as "63.6% compliant."

## JSON Compatibility Contract

The assessment artifact has its own schema version and does not replace the
analysis report. Schema version 1:

- uses deterministic key and list ordering where semantically ordered;
- emits decimal percentages as JSON numbers with one decimal place;
- emits timestamps in UTC RFC 3339 form;
- retains every control in the resolved policy after output filters are
  applied only to presentation;
- retains findings as evidence references, not duplicated raw secret-bearing
  evidence;
- rejects unknown input schema versions.

Future additive fields are allowed only within a documented assessment schema
version compatibility policy. A semantic status change requires a schema or
documented algorithm revision.

## Backward Compatibility

- Existing `analyze-*` commands remain usable without assessment.
- Existing text and JSON finding consumers are not redirected to this format.
- `assess` is a new command.
- Legacy analysis reports remain readable by existing report tools but are
  explicitly ineligible for control assessment.
- JSON additions required by follow-up 03 are additive to analysis output.
- Suppression behavior is unchanged; assessment only interprets its recorded
  state.
- Source coverage documentation and percentages are unchanged.
- No default CI gate is introduced.

## Error Handling

Required issue codes include:

```text
analysis_report_not_found
analysis_report_too_large
analysis_report_json_invalid
analysis_report_schema_unsupported
analysis_report_schema_invalid
analysis_report_hash_failed
ledger_validation_failed
ledger_hash_mismatch
registry_revision_mismatch
policy_metadata_missing
policy_hash_mismatch
policy_verification_mismatch
execution_manifest_missing
execution_manifest_invalid
finding_rule_unknown
finding_mapping_mismatch
finding_id_duplicate
suppression_reference_missing
required_evidence_missing
rule_execution_failed
rule_execution_skipped
conflicting_evidence
unassessable_legacy_report
unknown_source_filter
invalid_fail_on_status
output_exists
output_write_failed
```

Fatal input errors prevent artifact emission because provenance cannot be
trusted. Nonfatal control-level issues are included in the artifact and drive
`indeterminate`, `review`, or `not-assessed` as appropriate.

The CLI does not print tracebacks in normal operation. JSON mode reports fatal
errors in a small versioned error envelope when no assessment artifact can be
created.

## Security Considerations

- Treat analysis reports, policies, and custom ledgers as untrusted bounded
  input.
- Impose byte, target, finding, issue, control, and evidence count limits.
- Do not dereference report URLs or ticket/suppression references.
- Do not reopen analyzed configuration paths.
- Do not rerun probes during assessment.
- Verify hashes before trusting embedded policy and ledger identities.
- Escape terminal control characters and untrusted prose.
- Use atomic writes and safe output path handling.
- Avoid copying raw finding evidence that may contain credentials, cookies,
  authorization headers, filesystem secrets, or complete response bodies.
- Use report-local finding fingerprints that do not embed secret values.
- Make target display-name redaction follow existing report privacy behavior.
- Do not expose local absolute policy paths by default.
- Never treat a suppressed secret finding as resolved evidence.
- Do not support HTML in version 1, avoiding an additional rendering injection
  surface.

## Exact Likely Files

The implementation is expected to add or modify:

```text
src/webconf_audit/assessment.py
src/webconf_audit/assessment_models.py
src/webconf_audit/assessment_renderers.py
src/webconf_audit/coverage_models.py
src/webconf_audit/reporting.py
src/webconf_audit/models.py
src/webconf_audit/cli.py
tests/test_assessment_algorithm.py
tests/test_assessment_models.py
tests/test_assessment_cli.py
tests/test_assessment_renderers.py
tests/test_assessment_security.py
tests/fixtures/assessment/
docs/control-assessment.md
docs/report-format.md
docs/audit-policy.md
docs/control-source-coverage-tracker.md
README.md
```

`coverage_models.py` changes only to add explicit absence semantics after
evidence review. Existing rule files should not be changed merely to make
assessment statuses look better.

## Test Matrix

| Area | Case | Expected result |
| --- | --- | --- |
| Input | Valid current analysis report | Assessment produced |
| Input | Legacy report without policy/manifest | Fatal `unassessable_legacy_report` |
| Input | Oversized or malformed JSON | Rejected |
| Provenance | Ledger hash mismatch | Fatal |
| Provenance | Policy hash mismatch | Fatal |
| Provenance | Registry revision mismatch | Fatal or explicitly unsupported |
| Applicability | Explicit policy N/A | `not-applicable` with rationale |
| Applicability | Finding exists on N/A item | Retained as out-of-policy evidence |
| Uncovered | Required ledger item uncovered | `not-assessed` |
| Execution | Required rule not selected | `not-assessed` or `indeterminate` per reason |
| Execution | Required rule skipped | `indeterminate` |
| Execution | Target-wide parse/probe failure | Dependent controls `indeterminate` |
| Negative | Declared direct unsuppressed finding | `fail` |
| Negative | Partial-mapping finding | `partial` |
| Negative | Related-only finding | Context only, never independent `fail` |
| Negative | Derived OWASP 2025 finding | Context/partial only, never direct `fail` by itself |
| Suppression | Suppressed direct finding | `fail` with suppression provenance |
| Positive | Completed no-finding, absence `none` | No pass |
| Positive | All facet-pass evidence complete | At most `partial` unless full facet contract exists |
| Positive | Full ledger plus all direct control-pass checks | `pass` |
| Positive | One required control-pass rule missing | `indeterminate` |
| Policy review | HTTP/3 review rule completed | `review` |
| ASVS cookies | Findings map to corrected `3.3.x` items | Correct control evidence |
| ASVS CORS/COOP | Registry-backed findings | Correct `3.4.2`/`3.4.8` items |
| ASVS 3.4.7 | No CSP reporting finding | Never full-control pass from partial evidence |
| PCI | Stale combined `8.3.5 / 8.3.6` input | Mapping mismatch/fatal |
| Conflict | Positive and direct negative evidence | `fail`, conflict retained |
| Summary | All statuses | Identity invariant holds |
| Filtering | `--source` | Presentation filtered, calculation unchanged |
| Gate | Requested fail status present | Full output plus exit `3` |
| Gate | No requested status present | Exit `0` |
| Output | Existing file without force | No overwrite |
| Security | Terminal controls in titles/prose | Escaped |
| Security | Raw secret-bearing finding evidence | Not copied |
| Determinism | Same inputs twice | Equivalent deterministic JSON except declared generation time/report ID policy |

Golden fixtures should cover at least:

- local NGINX with a direct failure;
- local Apache with partial evidence;
- IIS with an analysis issue;
- external CORS and COOP findings;
- a zero-finding run with no pass semantics;
- HTTP/3 policy review;
- a suppressed finding;
- a derived OWASP 2025 mapping;
- the corrected PCI uncovered controls.

## Documentation Changes

Add `docs/control-assessment.md`:

- explain inputs and trust boundaries;
- define every assessment status;
- document status precedence;
- explain absence semantics;
- provide examples of fail, partial, review, indeterminate, not-assessed, and
  not-applicable;
- state why pass is intentionally restrictive;
- state that the artifact is not certification.

Update `docs/report-format.md`:

- specify the analysis metadata required for assessment;
- publish the version 1 assessment JSON schema;
- document finding fingerprints, hashes, and deterministic ordering.

Update `docs/audit-policy.md`:

- show how policy dispositions affect assessment without hiding findings;
- explain policy verification during `assess`.

Update `docs/control-source-coverage-tracker.md`:

- add a short cross-link stating that coverage status is not a target result;
- do not add assessment statuses to coverage totals.

Update `README.md`:

- add a minimal `assess` example;
- explain exit `3`;
- use "assessment" and "evidence" rather than "certification" or
  "compliance score."

## Coverage Impact

This design has no global coverage impact.

- Assessment statuses do not change ledger statuses.
- A target `pass` does not increase a full numerator.
- A target `fail` does not decrease a full numerator.
- A policy `not-applicable` does not remove an item from the package
  denominator.
- Assessment summaries are never used to calculate source coverage.
- Adding absence semantics does not itself justify a coverage increase; it
  requires its own rule-contract evidence review.

The corrected follow-up 01 and follow-up 02 baselines remain unchanged,
including:

- OWASP Top 10:2025 at zero full items until direct evidence exists;
- ASVS `3.4.7` as partial;
- corrected ASVS cookie, CORS, and COOP mappings;
- PCI controls conservatively partial or uncovered under corrected wording.

No percentage or numerator may rise because an assessment report was generated,
a target passed, a policy was approved, or a CI gate succeeded.

## Acceptance Criteria

1. `assess` accepts only versioned analysis reports with embedded resolved
   policy and a complete execution manifest.
2. Input hashes and registry revision are verified.
3. Every resolved policy control receives exactly one assessment status.
4. No-finding with default absence semantics never produces pass.
5. Pass requires explicit complete direct evidence and ledger status full.
6. Partial, related, and derived mappings cannot independently prove pass.
7. Direct negative findings remain failures even when suppressed.
8. Analyzer errors and missing evidence produce conservative statuses.
9. Corrected ASVS, OWASP 2025, and PCI mappings are preserved.
10. Text output clearly separates product coverage from target assessment.
11. JSON output is versioned, deterministic, and contains provenance.
12. No compliance percentage or certification language is emitted.
13. `--fail-on` gates only when explicitly requested and uses exit `3`.
14. Legacy reports fail clearly without being reinterpreted.
15. Existing analyzers and finding reports remain backward compatible.
16. No global coverage count changes.
17. Algorithm, CLI, renderer, compatibility, and security tests pass.

## Dependencies

- Follow-up 01: corrected mapping strength and origin.
- Follow-up 02: canonical ledger, stable IDs, summaries, and evidence
  relations.
- Follow-up 03: resolved policy, hashes, and execution manifest.
- Stable finding fingerprints and affected-rule analysis issue metadata.
- Existing Pydantic and Typer dependencies; no new runtime dependency is
  expected.

Assessment must not ship before the execution manifest is complete for all
supported analyzer modes.

## Rollback

Rollback is isolated:

1. remove the `assess` command and assessment modules;
2. stop publishing the assessment schema documentation;
3. retain analysis findings, corrected registry mappings, canonical ledger,
   policy support, and execution manifests;
4. preserve any generated assessment artifacts as historical outputs, marked
   with their schema version;
5. do not convert assessment statuses into suppressions or ledger edits.

If a status algorithm defect is found, disable assessment generation for the
affected schema version rather than silently changing old report meaning.

## Reviewer Checklist

- [ ] The artifact is clearly separate from the analysis finding report.
- [ ] Coverage status and assessment status are modeled separately.
- [ ] No-finding does not imply pass.
- [ ] Absence semantics default to `none`.
- [ ] Pass requires complete declared direct evidence.
- [ ] Partial, related, and derived evidence is capped conservatively.
- [ ] Suppressed direct findings remain failures and retain suppression
      provenance.
- [ ] Analyzer issues affect only dependent controls where possible.
- [ ] Every resolved control receives one deterministic status.
- [ ] Status precedence is documented and tested.
- [ ] Hashes, versions, policy, ledger, and registry provenance are verified.
- [ ] Legacy reports are rejected for assessment.
- [ ] ASVS cookie/CORS/COOP mappings are correct.
- [ ] ASVS `3.4.7` cannot report a full pass from current partial checks.
- [ ] OWASP 2025 derived mappings cannot prove direct outcomes.
- [ ] PCI wording does not restore the stale `8.3.5 / 8.3.6` claim.
- [ ] Reports contain no compliance percentage or certification claim.
- [ ] `--fail-on` is opt-in and still writes the complete artifact.
- [ ] Secret-bearing evidence is not copied.
- [ ] Global coverage counts and percentages remain unchanged.
- [ ] Tests cover all statuses, analyzers, drift cases, and security boundaries.
