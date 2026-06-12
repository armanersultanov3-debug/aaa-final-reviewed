# Follow-up 14: Final Cross-Standard Reconciliation Design

**Status:** Design specification
**Sequence:** follow-up 14 of 14
**Baseline:** PR #9 at `1e1cbbb` plus all accepted follow-ups 01-13
**Program dependencies:** every accepted evidence-domain follow-up
**Primary outcome:** atomically reconcile ledger, rule registry, generated documentation, counts, and limitations across CIS, OWASP, ASVS, NIST, PCI, and ISO

---

## 1. Inherited State

PR #9 establishes the conservative formula:

```text
Applicable = Full + Partial + Policy review + Uncovered
Full coverage = Full / Applicable
```

Only `full` increases the numerator. `partial`, `policy-review`, and
`uncovered` remain in the denominator. `excluded` is documented outside the
denominator.

The PR #9 pre-program snapshot is:

| Source | Applicable | Full | Partial | Policy review | Uncovered |
| --- | ---: | ---: | ---: | ---: | ---: |
| CIS NGINX v3.0.0 | 15 | 7 | 7 | 1 | 0 |
| CIS Apache 2.4 v2.3.0 | 19 | 17 | 2 | 0 | 0 |
| CIS IIS 10 v1.2.1 | 10 | 8 | 1 | 0 | 1 |
| OWASP Top 10:2025 | 8 | 2 | 6 | 0 | 0 |
| OWASP ASVS v5.0.0 | 22 | 15 | 7 | 0 | 0 |
| NIST SP 800-52 Rev. 2 | 10 | 10 | 0 | 0 | 0 |
| PCI DSS v4.0.1 | 11 | 11 | 0 | 0 | 0 |
| ISO/IEC 27002:2022 | 10 | 8 | 2 | 0 | 0 |

Follow-ups 01-13 may change:

- rule-to-standard mappings;
- source item granularity;
- mandatory subclaims;
- evidence bindings;
- source statuses;
- rule catalog counts;
- limitation wording.

Follow-up 14 is the only program-wide final recount. It does not pre-approve
the candidate promotions listed in earlier specifications.

Follow-up 01 deliberately corrects the starting crosswalk downward before the
ledger migration. The accepted follow-up 02 ledger, not the PR #9 prose table,
is therefore the immediate recount baseline. At design time that corrected
baseline is expected to include:

| Source | Applicable | Full | Partial | Policy review | Uncovered |
| --- | ---: | ---: | ---: | ---: | ---: |
| CIS NGINX v3.0.0 | 15 | 7 | 7 | 1 | 0 |
| CIS Apache 2.4 v2.3.0 | 19 | 17 | 2 | 0 | 0 |
| CIS IIS 10 v1.2.1 | 10 | 8 | 1 | 0 | 1 |
| OWASP Top 10:2025 | 8 | 0 | 8 | 0 | 0 |
| OWASP ASVS v5.0.0 | 22 | 14 | 8 | 0 | 0 |
| NIST SP 800-52 Rev. 2 | 10 | 10 | 0 | 0 | 0 |
| PCI DSS v4.0.1 | 11 | 0 | 9 | 0 | 2 |
| ISO/IEC 27002:2022 | 10 | 8 | 2 | 0 | 0 |

Implementation must load and validate the accepted packaged ledger rather than
copying these design-time values.

## 2. Exact Gaps

1. Coverage facts currently appear in multiple Markdown documents.
2. Rule counts and standards mappings are partly registry-derived and partly
   prose-maintained.
3. A domain PR can update implementation without every cross-standard
   consequence being visible.
4. The historical Apache Sections 4.1-4.2 grouping may conceal a denominator
   change after follow-up 11.
5. NIST and PCI 100% rows can be mistaken for compliance claims.
6. TLS evidence improvements can be over-propagated from one standard to
   another despite different control boundaries.
7. A new rule can update registry totals without updating all repeated
   documentation counters.
8. Partial merges can leave ledger, registry metadata, and prose inconsistent.
9. IIS FTP can be accidentally removed from the denominator or relabeled
   excluded during cleanup.

## 3. Goals

- Recompute every final count from the accepted machine-readable ledger.
- Validate every ledger evidence binding against the loaded rule registry.
- Reconcile CIS NGINX, CIS Apache, CIS IIS, OWASP Top 10:2025, OWASP ASVS
  v5.0.0, NIST SP 800-52 Rev. 2, PCI DSS v4.0.1, and ISO/IEC 27002:2022.
- Update registry mappings, ledger records, derived tables, repeated rule
  counts, and limitation prose in one atomic PR.
- Make numerator and denominator changes independently visible.
- Preserve partial and indeterminate boundaries.
- Prevent false compliance, certification, or organizational-control claims.
- Keep IIS FTP uncovered, applicable, and in the IIS denominator.
- Add CI guardrails that fail on any future drift.

## 4. Non-Goals

- Adding scanner behavior, parsers, probes, rules, or policy consumers.
- Repairing an incomplete evidence-domain implementation inside this PR.
- Promoting a source item because a schema, policy, or test fixture exists.
- Reclassifying broad organizational controls as fully implemented.
- Changing benchmark versions.
- Removing applicable items to improve percentages.
- Treating `related` references as direct evidence.
- Implementing IIS FTP.
- Writing an IIS FTP implementation specification.
- Claiming compliance with CIS, OWASP, ASVS, NIST, PCI, or ISO.

## 5. Atomic Reconciliation Unit

The following are one indivisible change:

1. machine-readable coverage ledger;
2. rule registry and standards metadata;
3. ledger-to-registry validation;
4. generated or synchronized coverage tables;
5. repeated rule inventory counters;
6. source-specific limitations;
7. exact numerator, denominator, and percentage calculations;
8. tests enforcing all of the above.

The PR is not ready if any layer is intentionally left for a later docs-only
change. A domain mismatch discovered during reconciliation is returned to the
relevant follow-up or fixed in a separate prerequisite PR, then the recount is
rerun from a clean baseline.

## 6. Source Of Truth And Derived Artifacts

Follow-up 02's machine-readable ledger is the source of truth. Its canonical
path is:

```text
src/webconf_audit/data/control_source_coverage.yml
```

The loaded rule registry is the source of truth for:

- rule IDs;
- category and server family;
- severity;
- primary and secondary standards references;
- opt-in tags;
- executable registration.

Markdown is derived presentation, not an independent authority.

Expected derived/synchronized artifacts:

- `docs/control-source-coverage-tracker.md`;
- the snapshot and methodology sections in `docs/benchmarks-covering.md`;
- per-rule inventory in `docs/rule-coverage.md`;
- accepted gap/status rows in `docs/standards-roadmap.md`;
- rule inventory counters in `README.md` and `docs/architecture.md`;
- any report-facing standard names or links affected by corrected registry
  metadata.

## 7. Recount Model

For each exact source version:

```python
SourceRecount(
    source_id,
    version,
    applicable,
    full,
    partial,
    policy_review,
    uncovered,
    excluded,
    full_coverage_percent,
)
```

Validation invariants:

```text
Applicable = Full + Partial + Policy review + Uncovered
Full coverage percent = round(100 * Full / Applicable, 1)
```

Additional invariants:

- every counted item has exactly one status;
- every item ID is unique within its source/version;
- every `full` item has all mandatory subclaims implemented;
- every mandatory subclaim has at least one valid evidence binding or an
  explicit non-rule evidence binding supported by follow-up 04;
- every rule binding resolves to a registered rule;
- no unknown registered rule is invented in docs;
- every excluded item has a scope reason;
- denominator changes carry a machine-readable reason;
- implementation PR references resolve to accepted program work;
- `category_alignment` and `organizational_control` claims use bounded wording.

## 8. Promotion Gate

An item may move to `full` only when the final branch contains:

- implemented evidence for every mandatory subclaim;
- positive and negative tests;
- scope/inheritance tests;
- incomplete/unknown evidence tests;
- CLI/API and JSON contract tests where relevant;
- registry metadata;
- source traceability;
- documented supported scope;
- documented limitations;
- no path that converts incomplete evidence into pass.

The following do not justify promotion:

- a policy schema without a consumer;
- a complete-looking synthetic fixture;
- one runtime handshake;
- one successful target;
- one config-visible `LoadModule` list;
- a v1 SChannel list with omissions;
- a documentation-only rule mapping;
- a related standard reference;
- a larger rule count.

If evidence is strong enough for one subclaim but not the whole item, the item
remains `partial`.

## 9. Cross-Standard Reconciliation Rules

### 9.1 CIS

- Recount NGINX, Apache, and IIS separately at exact benchmark versions.
- Use source IDs `cis-nginx-3.0.0`, `cis-apache-2.4-2.3.0`, and
  `cis-iis-1.2.1`.
- Preserve control-specific semantics rather than transferring status between
  server families.
- Apply the follow-up 11 Section 4.1/4.2 split explicitly.
- State whether that split changes the Apache denominator.
- Keep IIS FTP Sections 6.1/6.2 as one documented uncovered applicable item
  unless the accepted ledger already defines a different stable counted
  granularity without removing it.

### 9.2 OWASP Top 10:2025

- Use source ID `owasp-top10-2025`.
- Treat rows as category alignment within scanner scope.
- Do not infer application-wide coverage from server configuration evidence.
- Preserve partial status for categories with application, identity,
  supply-chain, or operational subclaims outside the scanner.

### 9.3 OWASP ASVS v5.0.0

- Use source ID `owasp-asvs-5.0.0`.
- Recount the exact grouped requirements defined by the ledger.
- Do not promote a group when only an observed route, cookie, TLS identity, or
  header instance passed.
- Keep runtime and application-context limitations explicit.

### 9.4 NIST SP 800-52 Rev. 2

- Use source ID `nist-sp-800-52r2`.
- Re-evaluate every TLS row against endpoint inventory and SChannel v2
  completeness.
- A previous 100% snapshot is not automatically preserved.
- Bounded cipher and revocation observations remain partial unless the ledger's
  exact subclaims are fully implemented.

### 9.5 PCI DSS v4.0.1

- Use source ID `pci-dss-4.0.1`.
- Use scanner-visible requirement slices, not PCI compliance language.
- Re-evaluate TLS, hardening, authentication, logging, and CSP mappings against
  accepted evidence boundaries.
- Organizational process, retention, governance, and validation remain outside
  scanner evidence.

### 9.6 ISO/IEC 27002:2022

- Use source ID `iso-iec-27002-2022`.
- Treat mappings as technical-control alignment.
- Keep monitoring, utility governance, and organizational implementation
  limits visible.
- Do not convert a technical signal into full organizational control
  implementation.

## 10. No-False-Compliance Language Contract

Allowed phrases:

- "scanner-evidence coverage within the documented scope";
- "counted source item";
- "bounded runtime evidence";
- "operator-declared complete inventory";
- "the current run passed the declared policy";
- "technical-control alignment";
- "partial" and "indeterminate".

Disallowed claims:

- "the project is CIS compliant";
- "OWASP compliant";
- "ASVS certified";
- "NIST compliant";
- "PCI DSS compliant";
- "ISO 27002 compliant";
- "fully implements the organizational control";
- "all TLS endpoints are secure" without a bounded declared inventory.

A test should scan the snapshot sections for prohibited compliance wording,
with a narrow allowlist for text that explicitly says the tool does *not*
certify compliance.

## 11. Reconciliation Workflow

1. Freeze the accepted merge SHAs for follow-ups 01-13.
2. Load all rule packages into a fresh registry.
3. Validate the ledger schema and item uniqueness.
4. Resolve every ledger rule/evidence binding.
5. Re-evaluate every mandatory subclaim.
6. Produce a before/after item-status diff.
7. Compute each source recount and denominator delta.
8. Render all derived tables to temporary files.
9. Compare generated output with tracked Markdown.
10. Update registry metadata, ledger, and docs in one change.
11. Run drift, wording, full-suite, and diff checks.
12. Have a reviewer independently reproduce the recount.

Generation must be deterministic:

- stable source order;
- stable item order;
- stable rule ID order;
- one decimal place for percentages;
- normalized line endings;
- no timestamps in generated Markdown unless explicitly required.

## 12. CLI And API

Extend the existing follow-up 02 `coverage` Typer group rather than creating a
parallel maintenance interface:

```text
webconf-audit coverage validate
webconf-audit coverage reconcile --check
webconf-audit coverage reconcile --write
```

`coverage show` and `coverage export` remain available with their follow-up 02
semantics. `reconcile` is the multi-document atomic operation; it reuses
`load_coverage_ledger`, `validate_coverage_ledger`,
`summarize_coverage`, and the existing deterministic renderers.

`--check`:

- performs no writes;
- exits nonzero for schema, registry, count, generated-doc, or wording drift;
- prints a concise source-by-source mismatch summary.

`--write`:

- validates all inputs before writing;
- renders every derived artifact to a temporary directory;
- replaces tracked outputs only after all rendering succeeds;
- never partially writes one document;
- does not alter implementation code or rule metadata automatically.

Library API:

```python
load_coverage_ledger(...)
validate_coverage_ledger(ledger, registry)
summarize_coverage(ledger)
reconcile_coverage_documents(ledger, registry)
check_coverage_reconciliation(...)
```

The command is a maintainer tool, not a scanner runtime command.

## 13. Behavior And Indeterminate States

The reconciliation itself either succeeds or fails validation. It does not
invent run assessments.

Validation fails when:

- an accepted follow-up dependency is missing;
- a ledger item or subclaim is malformed;
- a binding points to an unknown rule;
- a `full` item has missing mandatory evidence;
- generated docs differ from tracked docs in `--check`;
- equations or percentages do not reconcile;
- denominator change lacks a reason;
- IIS FTP is absent, excluded, or removed from the IIS denominator;
- prohibited compliance language appears;
- source versions are inconsistent;
- registry and per-rule docs disagree;
- a generated output would be only partially writable.

An evidence domain that remains indeterminate for real runs can still support
source capability only if the tool correctly models that indeterminate state.
If the capability itself is incomplete, the ledger status remains partial or
uncovered.

## 14. Likely Files

- machine-readable ledger created by follow-up 02;
- `src/webconf_audit/data/control_source_coverage.yml`;
- its schema/models and validation/generation package;
- `src/webconf_audit/rule_registry.py`;
- `src/webconf_audit/rule_standards.py`;
- rule modules whose accepted mappings require correction;
- `docs/control-source-coverage-tracker.md`;
- `docs/benchmarks-covering.md`;
- `docs/rule-coverage.md`;
- `docs/standards-roadmap.md`;
- `README.md`;
- `docs/architecture.md`;
- `tests/test_rule_coverage_doc.py`;
- new ledger integrity, recount, generation, wording, and mutation tests.

Follow-up 14 should not modify analyzers, parsers, probes, or rule behavior.

## 15. Migration And Backward Compatibility

- Existing report JSON standard references remain compatible unless a mapping
  is corrected by an accepted crosswalk decision.
- Rule IDs are not renamed.
- Existing finding fingerprints and baseline behavior are unchanged.
- Markdown becomes generated or strictly synchronized, but public document
  paths remain stable.
- Historical PR #9 counts remain documented as the before snapshot.
- New final counts are dated and tied to exact accepted commits.
- Any denominator change is called out separately from status promotions.
- The maintenance command is additive.

## 16. Exhaustive Test Plan

### Ledger integrity

- valid schema and exact source versions;
- unique item and subclaim IDs;
- allowed status and claim types;
- complete status equation;
- exclusion reasons;
- implementation PR references;
- denominator-change reasons.

### Registry integrity

- every bound rule exists;
- every documented rule exists;
- no duplicate or contradictory standard references;
- category/server family and opt-in metadata agree;
- accepted new rules appear in all rule inventory counts.

### Recount math

- each source's exact counts;
- zero and nonzero policy-review/uncovered cases;
- one-decimal percentage rounding;
- Apache denominator change from the 4.1/4.2 split, if accepted;
- mutation tests that alter each count and assert failure.

### Document generation

- deterministic output;
- `--check` clean on tracked files;
- `--write` renders all files atomically;
- simulated render failure writes nothing;
- stable line endings and ordering;
- repeated README/architecture/roadmap counters.

### Status gate

- `full` with a missing mandatory subclaim fails;
- related-only mapping cannot satisfy evidence;
- policy schema without assessment cannot promote;
- incomplete endpoint inventory cannot promote;
- incomplete Apache module snapshot cannot promote;
- v1 SChannel omission cannot promote;
- partial evidence stays partial.

### Language guardrail

- prohibited compliance phrases fail;
- explicit "does not certify compliance" wording passes;
- all 100% rows include scanner-scope limitations;
- OWASP/ISO category or control alignment wording is bounded.

### IIS FTP invariant

- FTP item exists;
- status is `uncovered`;
- item is applicable;
- item contributes to the IIS denominator;
- no FTP rule or implementation binding is introduced;
- generated docs display the limitation.

### Full repository verification

- full non-integration suite;
- relevant integration suites from accepted follow-ups;
- Ruff;
- interrogate;
- generator `--check`;
- `git diff --check`;
- independent recount script or reviewer worksheet comparison.

## 17. Documentation And Coverage Impact

This PR publishes the final post-program snapshot. It must include:

- PR #9 before counts;
- final counts;
- per-source numerator and denominator deltas;
- every item whose status changed;
- every item split or merged;
- unchanged partial/uncovered limitations;
- exact accepted implementation references.

No target final percentage is specified in advance. A lower percentage is a
valid result if corrected granularity or evidence honesty requires it.

The final IIS row must still show one uncovered FTP item in the denominator.
There is no FTP implementation spec in this program.

## 18. Acceptance Criteria

1. All accepted follow-ups 01-13 are represented.
2. Ledger, registry, counts, docs, and tests reconcile in one PR.
3. Every source equation and percentage is reproducible.
4. CIS, OWASP Top 10, ASVS, NIST, PCI, and ISO are all recounted.
5. Full items satisfy every mandatory subclaim.
6. Denominator changes are explicit.
7. No false compliance or certification language remains.
8. Reconciliation generation/checking is deterministic and atomic.
9. IIS FTP remains uncovered, applicable, visible, and in the denominator.
10. No scanner behavior or FTP implementation is added.

## 19. Dependencies

- Follow-ups 01-04 provide crosswalk, ledger, policy, and assessment
  foundations.
- Follow-ups 05-13 provide accepted evidence-domain behavior.
- Any rejected or unmerged follow-up is excluded and documented as not
  accepted rather than assumed complete.
- This PR is the terminal program recount.

## 20. Risks

- A generator can encode the same incorrect assumption as the ledger.
- Cross-standard mappings can inflate broad categories from narrow evidence.
- Denominator changes can be hidden by percentage improvements.
- Generated-doc churn can obscure substantive changes.
- A partial write can create inconsistent sources of truth.
- Existing 100% rows can invite compliance overclaims.

Mitigations include independent recount, item-level diffs, mutation tests,
atomic rendering, stable ordering, explicit denominator deltas, and wording
guardrails.

## 21. Rollback

- Revert the reconciliation PR as one unit.
- Restore ledger, registry metadata, generated docs, and tests together.
- Never roll back only the Markdown or only the ledger.
- Retain the last internally consistent snapshot.
- If a domain promotion is later found invalid, first revert or correct that
  domain evidence, then rerun the complete reconciliation.
- IIS FTP must remain uncovered and in the denominator throughout rollback.

## 22. Reviewer Checklist

- [ ] Accepted follow-up SHAs are frozen and listed.
- [ ] Every ledger binding resolves to real evidence.
- [ ] All source equations reconcile.
- [ ] Percentages are independently reproducible.
- [ ] Apache 4.1/4.2 granularity and denominator effect are explicit.
- [ ] Endpoint inventory, module snapshot, and SChannel completeness gates are enforced.
- [ ] Partial and policy-review items do not enter the numerator.
- [ ] OWASP and ISO mappings remain bounded alignments.
- [ ] NIST/PCI 100% rows, if retained, are scanner-scoped.
- [ ] No compliance or certification claim appears.
- [ ] Generated docs are deterministic and `--check` is clean.
- [ ] Rule inventory counters match the registry.
- [ ] IIS FTP is uncovered, applicable, visible, and in the denominator.
- [ ] No FTP implementation or implementation spec was added.
- [ ] The diff contains no analyzer behavior changes.
