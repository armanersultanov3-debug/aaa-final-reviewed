# Crosswalk Integrity Design

Date: 2026-06-12
Status: proposed
Sequence: follow-up 01 of 14

## Inherited State After PR #8 and PR #9

This design starts from `master` commit
`1e1cbbb7209a199282b28f823a0a7b07cc7df0bc`.

PR #8 introduced `docs/control-source-coverage-tracker.md` as the counted-item
ledger behind the source coverage percentages in
`docs/benchmarks-covering.md`. It made the denominator, numerator, grouped
items, and exclusions visible, but the ledger remained manually maintained
Markdown.

PR #9 refined the ledger vocabulary to:

- `full`;
- `partial`;
- `policy-review`;
- `uncovered`;
- `excluded`.

It also established these invariants:

```text
applicable = full + partial + policy-review + uncovered
full coverage percentage = full / applicable * 100
```

PR #9 deliberately kept rule category, severity, standard-reference strength,
and counted-item coverage status as separate concepts. It added
`nginx.http3_alt_svc_review`, retained opt-in policy review behavior, and did
not count partial or policy-review evidence in the full numerator.

The current mapping implementation is distributed across:

- inline `standards` declarations on decorated local and universal rules;
- `_EXTERNAL_RULE_METAS` in
  `src/webconf_audit/external/rules/_runner.py`;
- broad rule sets and generated references in
  `src/webconf_audit/rule_standards.py`;
- helper constructors in `src/webconf_audit/standards.py`;
- rendered inventory rows in `docs/rule-coverage.md`;
- manually summarized claims in
  `docs/control-source-coverage-tracker.md` and
  `docs/benchmarks-covering.md`;
- assertion samples in `tests/test_rule_registry_integrity.py`;
- inventory/count checks in `tests/test_rule_coverage_doc.py`.

The inherited tests prove that rule IDs and selected metadata are present.
They do not prove that every reference identifies the correct requirement,
that derived mappings are distinguished from reviewed mappings, or that a
counted `full` claim is supported by direct evidence.

## Problem

The repository currently contains confirmed crosswalk drift:

1. OWASP ASVS v5.0.0 cookie IDs are swapped or incomplete.
   `external.cookie_missing_httponly` is mapped to 3.3.2, although 3.3.4 is
   the `HttpOnly` requirement. `external.cookie_missing_samesite` and
   `external.cookie_samesite_none_without_secure` are mapped to 3.3.4,
   although 3.3.2 is the `SameSite` requirement. The `__Host-` aspect of
   `external.cookie_prefix_contract_violated` also relates to 3.3.3, which
   is absent from the grouped cookie ledger row.
2. The coverage tracker claims partial ASVS 3.4.2 CORS evidence, but
   `external.cors_wildcard_origin` and
   `external.cors_wildcard_with_credentials` have no ASVS reference in the
   registry.
3. The coverage tracker claims partial ASVS 3.4.8 COOP evidence, but
   `external.coop_missing` has no ASVS reference in the registry.
4. The tracker marks ASVS 3.4.7 CSP reporting as `full`, while every
   corresponding local and external rule reference is explicitly `partial`.
   The rules prove configured reporting syntax, not successful report
   delivery or endpoint operation.
5. OWASP Top 10:2025 references are automatically derived from reviewed 2021
   references. Reports expose them as secondary metadata, but the coverage
   tracker currently presents two 2025 categories as `full` without recording
   that the crosswalk is derived rather than independently reviewed.
6. PCI DSS wording and mappings overstate what the scanner observes.
   In particular, PCI DSS v4.0.1 8.3.5 concerns unique first-use/reset
   passwords and 8.3.6 concerns password length and composition. They do not
   describe cookie protection or generic credential-at-rest checks.
   Requirements 2.2.1, 6.2.4, 6.4.3, 8.3.1, 10.2.1, and 10.2.2 also contain
   organizational, SDLC, scope, activity, or payment-page conditions that a
   web-server configuration scanner does not fully prove.

These defects are integrity defects, not missing detector features. Adding
more prose without changing the authoritative metadata would preserve the
same failure mode.

## Goals

- Correct the confirmed ASVS, OWASP Top 10:2025, and PCI DSS mapping drift.
- Make mapping provenance explicit: reviewed declarations and derived
  alignments must be distinguishable in Python and JSON.
- Validate canonical standard/reference pairs used by the registry.
- Require every counted `full` item to have defensible direct evidence rather
  than only partial, related, or derived references.
- Keep the rule inventory, registry metadata, coverage tracker, benchmark
  summary, and tests synchronized.
- Make all known corrections conservatively. This change may lower coverage;
  it must not raise a numerator or remove an item from a denominator merely to
  offset a correction.
- Preserve analyzer detection behavior, finding severity, opt-in policy
  review behavior, and existing rule IDs.

## Non-Goals

- No new detector rules, probes, parsers, or runtime requests.
- No machine-readable control-source ledger in this change; that is follow-up
  02.
- No user-supplied audit policy; that is follow-up 03.
- No target-specific control assessment report; that is follow-up 04.
- No complete review of every external framework listed in
  `docs/benchmarks-covering.md`.
- No automatic claim that a valid standard ID is a semantically correct
  mapping.
- No implementation plan or task breakdown.

## Authoritative Sources

The review is grounded in the following exact source editions:

| Source ID | Edition | Authoritative location | Use |
| --- | --- | --- | --- |
| `owasp-asvs-5.0.0` | OWASP ASVS 5.0.0, V3 Web Frontend Security | `https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md` | Canonical cookie, CORS, CSP reporting, and COOP requirement IDs and wording. |
| `owasp-top10-2021` | OWASP Top 10:2021 | `https://owasp.org/Top10/` | Existing reviewed primary mappings. |
| `owasp-top10-2025` | OWASP Top 10:2025 | `https://owasp.org/Top10/2025/` | Current category identifiers and category changes. |
| `pci-dss-4.0.1` | PCI DSS Requirements and Testing Procedures v4.0.1, June 2024 | `https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf` | Exact requirement wording and applicability. |

Repository documentation or a third-party explanation may help locate a
requirement, but it is not sufficient evidence for a canonical crosswalk
change.

## Data Model and Design Decisions

The registry remains the runtime source of rule-to-standard references.
Integrity is added through a small canonical source catalog, explicit mapping
provenance, and reconciliation tests. The design does not move all mappings
into one large data file because inline mappings remain useful near detector
logic and follow-up 02 has a different purpose: counted source-item coverage.

### Standard Source Catalog

A new module defines the standard editions and the exact references that this
project currently uses for counted claims:

```python
StandardSourceId = Literal[
    "owasp-top10-2021",
    "owasp-top10-2025",
    "owasp-asvs-5.0.0",
    "pci-dss-4.0.1",
]

@dataclass(frozen=True)
class StandardItemDefinition:
    source_id: StandardSourceId
    standard: str
    reference: str
    title: str
    authoritative_url: str
    edition: str
```

The catalog is intentionally scoped to references requiring strict integrity
checks. It is not a copy of entire standards and must not embed copyrighted
standard text. `title` is a short project-authored label, not a verbatim
requirement.

### Mapping Provenance

`StandardReference` gains additive provenance fields:

```python
MappingOrigin = Literal["declared", "derived"]

@dataclass(frozen=True)
class StandardReference:
    standard: str
    reference: str
    url: str | None = None
    coverage: Literal["direct", "partial", "related"] = "direct"
    note: str | None = None
    tier: Literal["primary", "secondary"] = "primary"
    origin: MappingOrigin = "declared"
    derived_from_standard: str | None = None
    derived_from_reference: str | None = None
```

Invariants:

- `origin="declared"` requires both `derived_from_*` fields to be `None`.
- `origin="derived"` requires both `derived_from_*` fields.
- a derived reference is always `tier="secondary"`;
- derived references may be displayed and filtered but cannot independently
  support a counted `full` status;
- a duplicate is keyed by standard, reference, coverage, tier, origin, and
  derivation source, not just display text.

`owasp_top10_2025_references_from_primary()` sets `origin="derived"` and
records the source 2021 reference. A future independently reviewed 2025
mapping must be declared directly rather than routed through this function.

### Known Mapping Corrections

The exact expected ASVS corrections are:

| Rule ID | Required ASVS reference | Strength |
| --- | --- | --- |
| `external.cookie_missing_secure_on_https` | `v5.0.0-3.3.1` | `partial` |
| `external.cookie_missing_httponly` | `v5.0.0-3.3.4` | `partial` |
| `external.cookie_missing_samesite` | `v5.0.0-3.3.2` | `partial` |
| `external.cookie_samesite_none_without_secure` | `v5.0.0-3.3.2` | `partial` |
| `external.cookie_prefix_contract_violated` | `v5.0.0-3.3.1` and `v5.0.0-3.3.3` | `partial` for each |
| `external.cors_wildcard_origin` | `v5.0.0-3.4.2` | `partial` |
| `external.cors_wildcard_with_credentials` | `v5.0.0-3.4.2` | `partial` |
| `external.coop_missing` | `v5.0.0-3.4.8` | `partial` |

The cookie counted group is relabeled to include 3.3.3. This does not create a
new counted group or change the ASVS denominator.

ASVS 3.4.7 is changed from `full` to `partial` in the counted ledger because
all current evidence is configuration/header presence evidence.

### PCI DSS Correction Rules

PCI mappings must follow these constraints:

- the broad legacy 2.2.1 catch-all is `related`, not `direct`;
- 2.2.5 and 2.2.6 mappings are at most `partial` because the scanner cannot
  prove business justification, necessity, or complete in-scope system
  configuration;
- 4.2.1 mappings are at most `partial` because the scanner does not know
  whether a route transmits PAN over an open public network;
- 6.2.4 server-configuration mappings are removed or changed to `related`;
- 6.4.3 CSP mappings are `related`; the bounded cross-origin SRI rule may be
  `partial`, but no current rule proves payment-page script inventory,
  authorization, and integrity as a complete set;
- 8.3.1 mappings are `partial`;
- 8.3.2 is limited to transport/cryptographic evidence and is `partial`;
  cookie attribute rules do not map to it;
- the combined `Req. 8.3.5 / 8.3.6` reference is removed from
  `_AUTH_AT_REST_RULES`;
- 10.2.1 and 10.2.2 mappings are `partial` because enabled configuration and
  selected fields do not prove active logging across all in-scope components
  or all required event/detail semantics.

The project must not replace removed PCI references with a different
requirement unless the replacement is reviewed against the official wording.

## Internal API

The new validation surface is internal but deterministic:

```python
@dataclass(frozen=True)
class CrosswalkIssue:
    code: str
    rule_id: str | None
    standard: str | None
    reference: str | None
    message: str

def validate_standard_reference(ref: StandardReference) -> tuple[CrosswalkIssue, ...]:
    ...

def validate_registry_crosswalk(
    rules: Iterable[RuleMeta],
) -> tuple[CrosswalkIssue, ...]:
    ...
```

Required issue codes:

- `unknown_standard_reference`;
- `invalid_mapping_provenance`;
- `derived_reference_in_primary_tier`;
- `duplicate_cross_tier_reference`;
- `missing_mapping_note`;
- `coverage_claim_exceeds_evidence`;
- `coverage_tracker_registry_mismatch`.

The validator returns all issues in stable sort order. It does not stop at the
first invalid rule.

## CLI Contract

No analyzer command gains a new option in this follow-up.

`list-rules --format json` remains the public metadata inspection surface.
Each standard reference adds:

```json
{
  "origin": "declared",
  "derived_from": null
}
```

For a derived OWASP Top 10:2025 reference:

```json
{
  "origin": "derived",
  "derived_from": {
    "standard": "OWASP Top 10",
    "reference": "A05:2021"
  }
}
```

Text `list-rules` output is unchanged. Crosswalk validation is enforced by
tests and `scripts/release_check.py`; a dedicated end-user command is deferred
to follow-up 02, where it can validate the ledger and registry together.

## Backward Compatibility

- Rule IDs, finding payloads, severities, categories, tags, and analyzer
  defaults do not change.
- `StandardReference` construction remains source compatible because all new
  fields have defaults.
- Existing JSON consumers see additive fields only.
- Existing `standards` and `standards_secondary` arrays remain in place.
- Corrected references are intentional data corrections and are not treated
  as compatibility regressions.
- Baseline fingerprints remain stable because standards metadata is not part
  of the finding fingerprint.

## Error Handling

- Invalid built-in mappings fail tests and release checks.
- Registry loading raises `ValueError` only for structurally impossible
  provenance, such as `origin="derived"` without a source reference.
- Semantic catalog mismatches are accumulated as `CrosswalkIssue` values so a
  reviewer receives the complete defect list.
- Missing optional catalog coverage for non-counted standards is a warning,
  not an error.
- A counted source item whose evidence cannot be reconciled is an error and
  cannot silently retain `full`.
- Network failures cannot affect validation because authoritative sources are
  reviewed into the repository; validation performs no network requests.

## Security Considerations

- The canonical catalog contains identifiers, short labels, and URLs only; it
  does not copy licensed standard content.
- URLs are metadata and are never fetched during analyzer execution.
- Mapping notes must not contain target secrets, credentials, or probe output.
- No dynamic imports, templates, expressions, or executable mapping content
  are introduced.
- Derived mapping provenance prevents current-edition labels from being
  mistaken for independently reviewed compliance evidence.
- Conservative downgrades reduce the risk that reports misrepresent
  compliance to auditors or customers.

## Exact Likely Files

Expected implementation scope:

- `src/webconf_audit/rule_registry.py`
- `src/webconf_audit/standards.py`
- `src/webconf_audit/standard_catalog.py` (new)
- `src/webconf_audit/crosswalk_integrity.py` (new)
- `src/webconf_audit/rule_standards.py`
- `src/webconf_audit/external/rules/_runner.py`
- local CSP-reporting rule modules under
  `src/webconf_audit/local/{nginx,apache,lighttpd,iis}/rules/`
- `src/webconf_audit/cli/__init__.py`
- `src/webconf_audit/report/__init__.py`
- `scripts/release_check.py`
- `tests/test_standards.py`
- `tests/test_standards_helpers.py`
- `tests/test_rule_standards.py`
- `tests/test_rule_registry_integrity.py`
- `tests/test_rule_coverage_doc.py`
- `tests/test_crosswalk_integrity.py` (new)
- `tests/test_cli.py`
- `tests/test_report.py`
- `docs/rule-coverage.md`
- `docs/control-source-coverage-tracker.md`
- `docs/benchmarks-covering.md`
- `docs/standards-roadmap.md`
- `docs/architecture.md`
- `README.md` only if the JSON metadata contract is documented there

No detector behavior file outside mapping declarations should change.

## Test Matrix

| Area | Case | Expected result |
| --- | --- | --- |
| ASVS cookies | `HttpOnly` rule | Exactly one partial 3.3.4 reference; no 3.3.2 reference. |
| ASVS cookies | `SameSite` rules | Partial 3.3.2 references; no 3.3.4 references. |
| ASVS cookies | prefix rule | Partial 3.3.1 and 3.3.3 references. |
| ASVS CORS | both wildcard rules | Partial 3.4.2 references present in registry and rendered docs. |
| ASVS COOP | `external.coop_missing` | Partial 3.4.8 reference present. |
| ASVS reporting | all five CSP reporting rules | Registry references remain partial; tracker item is partial. |
| OWASP 2025 | generated 2025 reference | Secondary, derived, and linked to its 2021 source. |
| OWASP 2025 | derived reference used as sole full evidence | Integrity validation fails. |
| PCI | `Req. 8.3.5 / 8.3.6` | No registry reference remains. |
| PCI | broad 2.2.1 mapping | Related strength only. |
| PCI | 6.4.3 | CSP references related; bounded SRI at most partial. |
| PCI | logging | 10.2.1 and 10.2.2 references are partial. |
| provenance | declared reference with derivation fields | Validation error. |
| provenance | derived reference without source | Validation error. |
| serialization | `list-rules --format json` | Additive `origin` and `derived_from` fields are stable. |
| reports | finding standards metadata | Provenance is serialized without changing finding fingerprints. |
| docs | rule inventory | Registry/document mapping values agree. |
| regression | analyzers | Finding sets are unchanged for identical inputs. |
| regression | complete suite | All existing non-integration tests pass. |

## Documentation Changes

- `docs/rule-coverage.md` must render corrected ASVS and PCI mappings and
  explain declared versus derived references.
- `docs/control-source-coverage-tracker.md` must record the conservative
  recount below.
- `docs/benchmarks-covering.md` must use the same counts and explicitly state
  that OWASP Top 10:2025 automatic alignment is not independently reviewed
  full evidence.
- `docs/standards-roadmap.md` must close the known drift items but retain
  deeper framework review as future work.
- `docs/architecture.md` must describe mapping provenance and integrity
  validation.
- Documentation must not describe corrected metadata as new detector
  coverage.

## Coverage Impact

No coverage increase is allowed in this follow-up.

The expected conservative snapshot changes are:

| Source | Before | After |
| --- | --- | --- |
| OWASP ASVS v5.0.0 | 22 applicable, 15 full, 7 partial, 68.2% | 22 applicable, 14 full, 8 partial, 63.6% |
| OWASP Top 10:2025 | 8 applicable, 2 full, 6 partial, 25.0% | 8 applicable, 0 full, 8 partial, 0.0% |
| PCI DSS v4.0.1 | 11 applicable, 11 full, 0 partial, 100.0% | 11 applicable, 0 full, 9 partial, 2 uncovered, 0.0% |

For PCI DSS, 6.2.4 and the grouped 8.3.5/8.3.6 item remain visible as
`uncovered` in the inherited denominator rather than being silently excluded.
The remaining nine items become `partial`. A later denominator change requires
an explicit scope decision in the machine-readable ledger and cannot be
smuggled into a mapping correction.

All CIS, NIST, and ISO counts remain unchanged by this design. Any newly
discovered contradiction is resolved downward unless direct evidence is added
and separately reviewed.

## Acceptance Criteria

1. All confirmed ASVS cookie, CORS, COOP, and 3.4.7 drift is corrected in the
   registry, rendered inventory, and coverage tracker.
2. OWASP Top 10:2025 generated references identify themselves as derived from
   a specific 2021 reference.
3. A derived mapping cannot independently support `full` coverage.
4. PCI 8.3.5/8.3.6 is no longer attached to credential exposure or cookie
   rules.
5. PCI mapping strengths and tracker wording match the official requirement
   scope.
6. The exact conservative counts in the Coverage Impact section reconcile in
   both summary documents.
7. No detector, parser, probe, severity, rule ID, default rule selection, or
   baseline fingerprint changes.
8. Crosswalk validation reports all defects deterministically and performs no
   network access.
9. Focused and full regression tests pass.

## Dependencies

- Requires PR #8 and PR #9 as inherited state.
- Must land before follow-up 02 so the machine-readable ledger is seeded from
  corrected claims.
- Follow-up 03 and follow-up 04 consume the provenance and corrected
  crosswalk; they must not duplicate this logic.
- No new third-party package is required.

## Rollback

Rollback is a normal revert of the crosswalk-integrity change.

Because finding fingerprints and detector behavior do not change, rollback
does not require baseline migration. If the change is reverted, all
documentation counts, provenance serialization, catalog validation, and
mapping corrections must be reverted together. Partial rollback is forbidden:
retaining higher percentages while reverting supporting references would
recreate the integrity defect.

## Reviewer Checklist

- [ ] Review is based on the exact source editions listed above.
- [ ] Cookie IDs match ASVS 5.0.0 sections 3.3.1 through 3.3.4.
- [ ] CORS and COOP tracker claims have matching partial registry refs.
- [ ] ASVS 3.4.7 is not full while all evidence is partial.
- [ ] Derived OWASP 2025 mappings are visibly derived in Python and JSON.
- [ ] No derived mapping contributes to a full numerator.
- [ ] PCI wording matches v4.0.1 and no cookie/password-reset conflation
      remains.
- [ ] PCI broad catch-all mappings are not direct compliance claims.
- [ ] Coverage only stays the same or decreases.
- [ ] Denominators are unchanged in this correction follow-up.
- [ ] Analyzer outputs and finding fingerprints are unchanged.
- [ ] Documentation and registry values are tested for agreement.
- [ ] No implementation plan is included in this document.
