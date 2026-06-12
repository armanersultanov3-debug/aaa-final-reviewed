# Machine-Readable Coverage Ledger Design

Date: 2026-06-12
Status: proposed
Sequence: follow-up 02 of 14

## Inherited State After PR #8 and PR #9

This design starts from `master` commit
`1e1cbbb7209a199282b28f823a0a7b07cc7df0bc` and depends on the corrections
defined by
`2026-06-12-followup-01-crosswalk-integrity-design.md`.

PR #8 introduced `docs/control-source-coverage-tracker.md` as the counted-item
ledger behind the coverage percentages in `docs/benchmarks-covering.md`.
PR #9 refined the status vocabulary to:

- `full`;
- `partial`;
- `policy-review`;
- `uncovered`;
- `excluded`.

It also established:

```text
applicable = full + partial + policy-review + uncovered
full coverage percentage = full / applicable * 100
```

The tracker is still hand-maintained Markdown. Its summary rows, counted-item
rows, rule IDs, registry references, prose limitations, and benchmark
percentages can therefore disagree without producing a machine failure.
Current tests primarily verify selected rule references, sample findings, and
headline counts. They do not parse and reconcile every tracker row with the
registry.

Follow-up 01 corrects known crosswalk drift before this ledger becomes
canonical:

- ASVS cookie IDs are aligned with ASVS 5.0 requirements `3.3.1` through
  `3.3.4`;
- ASVS CORS `3.4.2` and COOP `3.4.8` receive the missing registry references;
- ASVS `3.4.7` is consistently `partial`, not `full`;
- OWASP Top 10:2025 mappings derived from 2021 are marked as derived and cannot
  independently support `full`;
- PCI DSS wording and mapping strength are corrected, including removal of the
  unsupported combined `8.3.5 / 8.3.6` credential-at-rest claim.

The machine-readable ledger must be populated from that corrected state, not
from the known-drifting pre-correction tracker.

## Problem

Coverage is a release-significant claim, but its source of truth is prose.
There is no typed representation of:

- source identity and version;
- counted-item identity;
- grouped requirements;
- applicability and exclusions;
- supporting rule IDs and registry references;
- evidence limitations;
- mapping origin;
- expected totals and percentages;
- review provenance.

As a result, a typo, stale rule ID, unsupported `full` claim, changed
denominator, or derived-only mapping can be merged while the Markdown remains
plausible to a reviewer.

The project needs one bounded, reviewable, machine-readable ledger from which
coverage totals can be validated and documentation can be rendered. It must
not infer better coverage merely because a rule or standard reference exists.

## Goals

1. Define a versioned schema for every counted source and item.
2. Make the package ledger the canonical source for coverage counts.
3. Validate ledger entries against the rule registry and source catalog.
4. Preserve the PR #9 status vocabulary and calculation formula.
5. Represent grouped references, exclusions, limitations, and provenance
   explicitly.
6. Distinguish declared mappings from derived mappings.
7. Require evidence adequate for the claimed status.
8. Produce deterministic Markdown and JSON views.
9. Fail release checks when the checked-in view or summary drifts.
10. Migrate without increasing any full-coverage numerator.

## Non-Goals

- Implementing new audit rules or changing analyzer behavior.
- Automatically deciding that a control is fully covered.
- Treating a registry reference as proof of full requirement coverage.
- Replacing upstream standards with local copies.
- Fetching standards or schemas from the network at runtime.
- Defining organization-specific audit policy.
- Assessing a particular analyzed target.
- Generating a compliance certificate.
- Adding implementation plans to this design series.

## Exact Sources in Scope

The initial ledger contains the same eight source families counted after PR
#9, with versions and authoritative locations made explicit:

| Source ID | Counted source | Authority |
| --- | --- | --- |
| `cis-nginx-3.0.0` | CIS NGINX Benchmark v3.0.0 | `https://www.cisecurity.org/benchmark/nginx` |
| `cis-apache-http-server-2.4-2.3.0` | CIS Apache HTTP Server 2.4 Benchmark v2.3.0 | `https://www.cisecurity.org/benchmark/apache_http_server` |
| `cis-microsoft-iis-10-1.2.1` | CIS Microsoft IIS 10 Benchmark v1.2.1 | `https://www.cisecurity.org/benchmark/microsoft_iis` |
| `owasp-top10-2025` | OWASP Top 10:2025 | `https://owasp.org/Top10/2025/` |
| `owasp-asvs-5.0.0` | OWASP ASVS 5.0.0, web/frontend subset currently counted | `https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md` plus referenced ASVS chapters |
| `nist-sp-800-52r2` | NIST SP 800-52 Rev. 2 selected requirements | `https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final` |
| `pci-dss-4.0.1` | PCI DSS v4.0.1 selected requirements | `https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf` |
| `iso-iec-27002-2022` | ISO/IEC 27002:2022 selected controls | `https://www.iso.org/standard/75652.html` and the licensed-source boundary used by the tracker |

The ledger records only the selected controls currently counted by the
project. It does not imply that an entire source has been exhaustively
imported.

Follow-up 01 introduces the strict catalog entries needed for the corrected
ASVS, OWASP, and PCI crosswalk. This follow-up extends that same catalog model
to all eight ledger sources above; it does not create a competing source
registry.

## Canonical Storage

The canonical file is:

```text
src/webconf_audit/data/control_source_coverage.yml
```

Reasons for package storage:

- installed CLI builds can validate and display the exact ledger shipped with
  their rule registry;
- tests can load it without depending on repository-relative documentation;
- release artifacts retain the claims they were built with.

`docs/control-source-coverage-tracker.md` remains a stable human-facing path
but becomes a deterministic rendered view. A generated-file notice identifies
the canonical YAML and the command used to check or refresh the view.

No YAML includes, custom tags, merge keys, executable constructors, or remote
references are allowed.

## Data Model

### Scalar Types

```python
SchemaVersion = Literal[1]
CoverageStatus = Literal[
    "full",
    "partial",
    "policy-review",
    "uncovered",
    "excluded",
]
Applicability = Literal["applicable", "excluded"]
MappingStrength = Literal["direct", "partial", "related"]
MappingOrigin = Literal["declared", "derived"]
EvidenceKind = Literal[
    "local-config",
    "normalized-config",
    "registry-export",
    "safe-probe",
    "policy-review",
]
SourceID = str
ItemID = str
RuleID = str
ISODate = date
```

IDs use lowercase ASCII letters, digits, dots, and hyphens:

```regex
^[a-z0-9][a-z0-9.-]*$
```

They are stable identifiers, not display labels.

### Root Schema

```python
class CoverageLedger(BaseModel):
    schema_version: Literal[1]
    snapshot: LedgerSnapshot
    sources: tuple[CoverageSource, ...]
```

```python
class LedgerSnapshot(BaseModel):
    snapshot_id: str
    effective_date: date
    base_revision: str
    description: str
```

`base_revision` records the Git revision whose registry and claims were
reviewed. It is provenance, not a runtime requirement that the current checkout
have the same HEAD.

### Source Schema

```python
class CoverageSource(BaseModel):
    source_id: SourceID
    title: str
    version: str
    authority_url: AnyHttpUrl
    scope_note: str
    expected_summary: CoverageSummary
    items: tuple[CoverageItem, ...]
```

```python
class CoverageSummary(BaseModel):
    applicable: NonNegativeInt
    full: NonNegativeInt
    partial: NonNegativeInt
    policy_review: NonNegativeInt
    uncovered: NonNegativeInt
    excluded: NonNegativeInt
    full_percent: Decimal
```

`full_percent` is serialized with one decimal place and calculated using
decimal arithmetic:

```text
round_half_up(full / applicable * 100, 1)
```

When `applicable == 0`, `full_percent` is `0.0`; division by zero is never
attempted.

### Counted Item Schema

```python
class CoverageItem(BaseModel):
    item_id: ItemID
    title: str
    references: tuple[ControlReference, ...]
    applicability: Applicability
    status: CoverageStatus
    evidence: CoverageEvidence
    exclusion: Exclusion | None = None
    provenance: ItemProvenance
```

```python
class ControlReference(BaseModel):
    standard: str
    reference: str
    grouped_references: tuple[str, ...] = ()
```

`reference` is the tracker display value. `grouped_references` names each
underlying requirement when one counted item intentionally groups multiple
requirements. Grouping is explicit and remains one denominator item.

### Evidence Schema

```python
class CoverageEvidence(BaseModel):
    rule_ids: tuple[RuleID, ...] = ()
    registry_references: tuple[RegistryReferenceClaim, ...] = ()
    evidence_kinds: tuple[EvidenceKind, ...] = ()
    rationale: str
    limitations: tuple[str, ...] = ()
```

```python
class RegistryReferenceClaim(BaseModel):
    rule_id: RuleID
    standard: str
    reference: str
    strength: MappingStrength
    origin: MappingOrigin
```

The claim duplicates only the registry fields required to make a reviewed
coverage assertion stable and diffable. Validation requires an exact match
with the live registry. It is not a second editable registry.

For a derived mapping:

```python
origin == "derived"
```

and the corresponding live `StandardReference` must expose its derivation
provenance as defined by follow-up 01.

### Exclusion and Provenance

```python
class Exclusion(BaseModel):
    reason: str
    boundary: str
```

```python
class ItemProvenance(BaseModel):
    reviewed_on: date
    source_url: AnyHttpUrl
    change_ref: str
```

`change_ref` is a PR, issue, commit, or design identifier. It is not dereferenced
by the loader.

## Example Shape

```yaml
schema_version: 1
snapshot:
  snapshot_id: post-pr9-crosswalk-correction
  effective_date: 2026-06-12
  base_revision: 1e1cbbb7209a199282b28f823a0a7b07cc7df0bc
  description: Corrected baseline before machine-readable migration.
sources:
  - source_id: owasp-asvs-5.0.0
    title: OWASP Application Security Verification Standard
    version: "5.0"
    authority_url: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md
    scope_note: Selected HTTP and web frontend requirements currently counted.
    expected_summary:
      applicable: 22
      full: 14
      partial: 8
      policy_review: 0
      uncovered: 0
      excluded: 0
      full_percent: 63.6
    items:
      - item_id: asvs-3.4.7-csp-reporting
        title: CSP reporting endpoint
        references:
          - standard: OWASP ASVS 5.0
            reference: V3.4.7
            grouped_references: []
        applicability: applicable
        status: partial
        evidence:
          rule_ids:
            - nginx.csp_reporting_missing
            - apache.csp_reporting_missing
            - lighttpd.csp_reporting_missing
            - iis.csp_reporting_missing
            - external.csp_reporting_missing
          registry_references:
            - rule_id: nginx.csp_reporting_missing
              standard: OWASP ASVS 5.0
              reference: V3.4.7
              strength: partial
              origin: declared
          evidence_kinds:
            - local-config
            - safe-probe
            - registry-export
          rationale: The rules detect selected missing reporting directives.
          limitations:
            - They do not validate receiver ownership, availability, retention, or response handling.
        exclusion: null
        provenance:
          reviewed_on: 2026-06-12
          source_url: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md
          change_ref: followup-01-crosswalk-integrity
```

The real migration must enumerate every supporting registry reference, not
retain this abbreviated example.

## Validation Invariants

Validation has four layers.

### Schema Validation

- only schema version `1` is accepted;
- unknown fields are rejected;
- IDs and URLs must satisfy their declared types;
- source IDs and item IDs are unique;
- duplicate registry claims are rejected;
- empty titles, rationale, scope notes, and provenance values are rejected.

### Status and Applicability Validation

- `status == "excluded"` requires `applicability == "excluded"` and a
  non-empty `exclusion`;
- every other status requires `applicability == "applicable"` and
  `exclusion is None`;
- `full` requires at least one declared, direct registry claim and at least one
  non-registry evidence kind;
- derived references cannot independently satisfy the `full` requirement;
- `partial` requires at least one real rule or policy-review evidence item and
  at least one explicit limitation;
- `policy-review` requires a rule tagged `policy-review` or an explicit
  policy-review evidence record;
- `uncovered` cannot contain a positive supporting rule claim; related rules
  may be mentioned only in rationale, not in `rule_ids`;
- `excluded` cannot contain supporting rules.

These are minimum integrity rules. They do not automatically upgrade a status.

### Registry Reconciliation

For every `rule_id`:

- the rule exists in the built registry;
- the ledger claim matches standard, reference, strength, and origin exactly;
- a secondary or derived reference is not silently treated as primary;
- an opt-in rule is identified as such;
- a rule referenced by a `full` item is not merely `related`.

For every counted control reference:

- the source exists in the expanded source catalog whose model begins in
  follow-up 01;
- the reference format is valid for that source;
- deprecated aliases produce an error, not automatic rewriting.

### Summary Reconciliation

Computed totals must exactly equal `expected_summary`. The validator also
reconciles the source summaries rendered in:

- `docs/control-source-coverage-tracker.md`;
- `docs/benchmarks-covering.md`.

There is no tolerance for count differences. Percentage text must match the
one-decimal deterministic calculation.

## Application API

The proposed internal API is:

```python
def load_coverage_ledger(
    path: Path | None = None,
) -> CoverageLedger: ...

def validate_coverage_ledger(
    ledger: CoverageLedger,
    registry: RuleRegistry,
    catalog: StandardCatalog,
) -> tuple[CoverageLedgerIssue, ...]: ...

def summarize_coverage(
    ledger: CoverageLedger,
) -> tuple[SourceCoverageSummary, ...]: ...

def render_coverage_markdown(
    ledger: CoverageLedger,
) -> str: ...

def render_coverage_json(
    ledger: CoverageLedger,
) -> str: ...

def check_coverage_documentation(
    ledger: CoverageLedger,
    tracker_path: Path,
    benchmark_path: Path,
) -> tuple[CoverageLedgerIssue, ...]: ...
```

```python
class CoverageLedgerIssue(BaseModel):
    code: str
    message: str
    source_id: str | None = None
    item_id: str | None = None
    rule_id: str | None = None
    path: str | None = None
```

All returned issue sequences are sorted by source ID, item ID, rule ID, and
code for deterministic output.

## CLI Design

Add a `coverage` Typer command group:

```text
webconf-audit coverage validate
webconf-audit coverage validate --ledger PATH --format json
webconf-audit coverage show
webconf-audit coverage show --source owasp-asvs-5.0.0
webconf-audit coverage show --status partial --format json
webconf-audit coverage export --format markdown
webconf-audit coverage export --format markdown --output PATH
```

Behavior:

- omitted `--ledger` loads the packaged canonical ledger;
- a custom ledger is local-only and must pass the same validation;
- `show` computes summaries and filters items without changing them;
- `export` writes deterministic content and refuses to overwrite an existing
  file unless `--force` is supplied;
- stdout is used when `--output` is omitted;
- text errors go to stderr;
- JSON output has a stable top-level `schema_version`, `valid`, `issues`, and
  `sources` shape.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Valid ledger or successful display/export |
| `1` | File, YAML, schema, registry, or documentation integrity failure |
| `2` | Invalid CLI usage |

The release check calls the application API directly rather than shelling out.

## Backward Compatibility

- Existing analysis commands and default rule selection are unchanged.
- Existing finding JSON remains unchanged by this follow-up.
- Existing Markdown URLs remain valid.
- The tracker layout should remain recognizably equivalent, but exact
  whitespace and table ordering become deterministic.
- New CLI commands are additive.
- The schema is versioned from its first release; unknown future versions fail
  clearly.
- No status aliases such as `covered`, `review`, or `n/a` are accepted.
- Existing percentages are migrated only after follow-up 01 corrections; the
  migration does not preserve known-invalid headline claims for compatibility.

## Error Handling

Required issue codes include:

```text
ledger_file_not_found
ledger_file_too_large
ledger_yaml_invalid
ledger_schema_unsupported
ledger_schema_invalid
duplicate_source_id
duplicate_item_id
invalid_status_applicability
missing_exclusion_reason
unexpected_exclusion
unknown_source_reference
unknown_rule_id
registry_reference_missing
registry_reference_mismatch
derived_reference_used_for_full
insufficient_full_evidence
insufficient_partial_evidence
invalid_policy_review_evidence
uncovered_item_has_positive_evidence
summary_count_mismatch
summary_percentage_mismatch
tracker_render_drift
benchmark_summary_drift
output_exists
output_write_failed
```

YAML parser exceptions are wrapped without a Python traceback in normal CLI
mode. JSON mode emits structured issues. Unexpected internal exceptions retain
the existing project-level failure handling and may show a traceback only when
the existing debug mode is active.

Multiple semantic issues are accumulated in one pass where safe. Parsing and
schema failures stop reconciliation because no trustworthy model exists.

## Security Considerations

- Load with `yaml.safe_load` or the Pydantic-integrated equivalent.
- Reject custom tags, merge keys, and non-scalar mapping keys.
- Impose a bounded input size for custom ledgers before parsing.
- Bound source, item, evidence, and limitation counts to avoid memory
  amplification.
- Do not resolve URLs, local includes, environment variables, or aliases to
  external content.
- Treat all prose and IDs as untrusted when rendering terminal output.
- Escape Markdown table delimiters and line breaks deterministically.
- Use atomic replacement for `--output`; do not follow an output symlink when
  a safer same-directory temporary file cannot be established.
- Never put secrets, analyzed configuration content, or target paths in the
  coverage ledger.
- Authority URLs are citations only and are never fetched by validation.

## Exact Likely Files

The implementation is expected to add or modify only the following product
areas:

```text
src/webconf_audit/data/control_source_coverage.yml
src/webconf_audit/coverage_ledger.py
src/webconf_audit/coverage_models.py
src/webconf_audit/cli.py
src/webconf_audit/standard_catalog.py
scripts/release_check.py
tests/test_coverage_ledger.py
tests/test_coverage_cli.py
tests/test_release_check.py
docs/control-source-coverage-tracker.md
docs/benchmarks-covering.md
docs/standards-mapping.md
README.md
```

`src/webconf_audit/standard_catalog.py` is inherited from follow-up 01 and
extended here from the drift-sensitive subset to all eight counted sources. If
the project keeps models and behavior in one module, `coverage_models.py` may
be folded into `coverage_ledger.py`; a second representation must not be
created.

No analyzer implementation file should need modification.

## Test Matrix

| Area | Case | Expected result |
| --- | --- | --- |
| Loading | Packaged version 1 ledger | Parses successfully |
| Loading | Missing file | `ledger_file_not_found` |
| Loading | Oversized custom file | Rejected before YAML parse |
| Loading | Unsafe YAML tag or merge key | Rejected |
| Schema | Unknown field | Rejected |
| Schema | Duplicate source/item ID | Rejected deterministically |
| Status | Excluded without exclusion | Rejected |
| Status | Applicable item marked excluded | Rejected |
| Full evidence | Declared direct reference plus adequate evidence | Valid |
| Full evidence | Derived-only OWASP 2025 mapping | Rejected |
| Full evidence | Related-only mapping | Rejected |
| Partial evidence | No limitation | Rejected |
| Policy review | Rule lacks policy-review tag | Rejected |
| Uncovered | Contains supporting rule ID | Rejected |
| Registry | Missing CORS/COOP ASVS ref | Rejected |
| Registry | Wrong ASVS cookie ID | Rejected |
| Registry | ASVS 3.4.7 ledger full while registry partial | Rejected |
| Registry | PCI 8.3.5/8.3.6 unsupported claim | Rejected |
| Summary | One item status changed without summary update | Rejected |
| Percentage | Incorrect rounding or stale text | Rejected |
| Rendering | Same ledger rendered twice | Byte-identical output |
| Docs | Tracker manually edited | Release check fails |
| Docs | Benchmark percentage stale | Release check fails |
| CLI | Text validation success | Exit `0` |
| CLI | JSON validation failure | Exit `1`, structured issues |
| CLI | Export existing file without force | Exit `1`, no overwrite |
| Compatibility | Existing analyze commands | Output and selection unchanged |

Property-based tests should generate status combinations to verify the summary
identity and percentage calculation. Snapshot tests are appropriate for the
rendered tracker only after semantic assertions cover every row.

## Documentation Changes

`docs/control-source-coverage-tracker.md`:

- add generated-view notice;
- retain the status definitions and calculation formula;
- render source summaries and every item from the ledger;
- retain rationale and limitation text without collapsing it into status.

`docs/benchmarks-covering.md`:

- state that percentages are generated from the packaged ledger;
- link to the canonical schema documentation and human tracker;
- retain the distinction between full and partial coverage.

`docs/standards-mapping.md`:

- explain declared versus derived references;
- state that registry mappings and coverage statuses are reconciled but remain
  distinct concepts.

`README.md`:

- document `coverage validate`, `coverage show`, and `coverage export`;
- avoid presenting coverage as certification.

## Coverage Impact

This follow-up is a representation and enforcement change. It must not increase
coverage.

Its migration baseline is the corrected outcome from follow-up 01:

| Source | Applicable | Full | Partial | Policy review | Uncovered | Full % |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CIS NGINX | 15 | 7 | 7 | 1 | 0 | 46.7 |
| CIS Apache | 19 | 17 | 2 | 0 | 0 | 89.5 |
| CIS IIS | 10 | 8 | 1 | 0 | 1 | 80.0 |
| OWASP Top 10:2025 | 8 | 0 | 8 | 0 | 0 | 0.0 |
| OWASP ASVS 5.0 | 22 | 14 | 8 | 0 | 0 | 63.6 |
| NIST SP 800-52 Rev. 2 | 10 | 10 | 0 | 0 | 0 | 100.0 |
| PCI DSS v4.0.1 | 11 | 0 | 9 | 0 | 2 | 0.0 |
| ISO/IEC 27002:2022 | 10 | 8 | 2 | 0 | 0 | 80.0 |

The implementation must preserve those values exactly unless a later,
separately reviewed evidence change proves a different status. A migration
script, schema validator, or successful registry match is not evidence for an
upgrade.

Any future numerator increase requires:

1. an authoritative source citation;
2. declared registry mapping;
3. rule behavior tests for the relevant requirement;
4. limitations review;
5. an explicit ledger diff and summary change;
6. reviewer confirmation that the evidence covers the complete counted item.

## Acceptance Criteria

1. A schema-versioned package ledger enumerates every currently counted item.
2. All corrected follow-up 01 statuses and totals are represented exactly.
3. Every supporting rule ID and registry claim reconciles with the live
   registry.
4. Derived-only OWASP 2025 mappings cannot validate a `full` item.
5. The corrected ASVS cookie, CORS, COOP, and `3.4.7` states are enforced.
6. Unsupported PCI wording cannot re-enter through a ledger-only edit.
7. `coverage validate` fails on semantic or documentation drift.
8. Tracker Markdown is deterministic and checked in.
9. Existing analyzers behave identically when coverage commands are unused.
10. No full numerator is increased by the migration.
11. Unit, integration, CLI, rendering, and release-check tests pass.
12. Documentation clearly separates source coverage from target compliance.

## Dependencies

- Follow-up 01 must land first or in the same atomic change.
- The source catalog model and crosswalk validation fields from follow-up 01
  are required; this follow-up adds catalog entries for the remaining counted
  editions.
- Existing Pydantic and PyYAML dependencies are sufficient; no new runtime
  dependency is expected.
- Follow-up 03 consumes item IDs and source IDs from this ledger.
- Follow-up 04 consumes the ledger but cannot mutate it.

## Rollback

Rollback is additive and data-preserving:

1. remove the `coverage` CLI group and release-check hook;
2. stop packaging the YAML ledger;
3. restore the last generated tracker as manually maintained Markdown;
4. leave follow-up 01 registry corrections intact;
5. do not restore pre-correction ASVS, OWASP, or PCI claims.

If the schema proves too restrictive, increment the schema version or relax the
validator in a reviewed change. Do not silently accept unknown fields or
rewrite version 1 data in place.

## Reviewer Checklist

- [ ] The ledger starts from commit `1e1cbbb` plus follow-up 01 corrections.
- [ ] Every source and counted item has a stable unique ID.
- [ ] Grouped references are explicit and counted once.
- [ ] Status/applicability/exclusion invariants are enforced.
- [ ] Full items require declared direct evidence beyond registry presence.
- [ ] Derived OWASP 2025 references cannot support full coverage alone.
- [ ] ASVS cookie IDs match requirements `3.3.1` through `3.3.4`.
- [ ] CORS `3.4.2` and COOP `3.4.8` registry evidence is reconciled.
- [ ] ASVS `3.4.7` is partial in registry, ledger, and docs.
- [ ] PCI wording and mapping strength match the authoritative requirement.
- [ ] Expected summaries match computed summaries exactly.
- [ ] Markdown and benchmark claims are generated or checked deterministically.
- [ ] Custom YAML loading is bounded and uses a safe parser.
- [ ] Existing analyzer behavior and output remain compatible.
- [ ] The migration does not increase any full numerator.
- [ ] Tests cover every validation layer and every known drift case.
