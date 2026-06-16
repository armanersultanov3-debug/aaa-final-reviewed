# NIST TLS Evidence Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote NIST SP 800-52 Rev. 2 TLS coverage rows to `full` only through complete declared TLS inventory evidence.

**Architecture:** The PR keeps runtime TLS inventory behavior intact and strengthens the coverage ledger, reconciliation guardrails, and generated documentation. `external.tls_inventory` remains the control assessment that proves inventory-scoped endpoint/SNI evidence; ledger `full` is valid only when subclaims bind to that control with required facets.

**Tech Stack:** Python, Pydantic coverage models, YAML coverage ledger, Typer CLI, pytest, ruff.

---

### Task 1: Add NIST TLS Coverage Guardrail Tests

**Files:**
- Modify: `tests/test_coverage_ledger.py`

- [ ] **Step 1: Write failing tests**

Add tests that load the packaged ledger, find the four NIST TLS items, and assert each full item has:

```python
def _coverage_item(ledger, source_id: str, item_id: str):
    source = next(source for source in ledger.sources if source.source_id == source_id)
    return next(item for item in source.items if item.item_id == item_id)


def test_nist_tls_full_items_require_tls_inventory_control_subclaims() -> None:
    ledger = load_coverage_ledger()
    required = {
        "nist-3.3.1-recommended-cipher-posture": {"negotiated_cipher"},
        "nist-3.3.2-server-cipher-preference": {"negotiated_cipher"},
        "nist-4.2-ocsp-must-staple": {"ocsp_stapling"},
        "nist-4.3-revocation-evidence": {"ocsp_stapling"},
    }

    for item_id, facets in required.items():
        item = _coverage_item(ledger, "nist-sp-800-52r2", item_id)
        assert item.status == "full"
        control_bindings = [
            binding
            for subclaim in item.subclaims
            for binding in subclaim.bindings
            if binding.kind == "control"
            and binding.target == "external.tls_inventory"
        ]
        assert control_bindings
        assert any(
            control.absence_semantics == "control-pass"
            and control.strength == "direct"
            for control in control_bindings
        )
        assessed = {
            facet
            for control in item.evidence.assessment_controls
            if control.control_id == "external.tls_inventory"
            for facet in control.assessed_facets
        }
        assert facets.issubset(assessed)
```

Add a negative validation test that mutates one full NIST item by removing its
TLS inventory assessment control and expects `check_coverage_reconciliation` to
emit a specific issue.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
uv run --locked pytest tests\test_coverage_ledger.py::test_nist_tls_full_items_require_tls_inventory_control_subclaims -q
```

Expected: FAIL because the current packaged ledger keeps these items `partial`.

### Task 2: Implement NIST TLS Reconciliation Guardrail

**Files:**
- Modify: `src/webconf_audit/coverage_ledger.py`
- Modify: `tests/test_coverage_ledger.py`

- [ ] **Step 1: Add validation helper**

Add a helper called `_validate_nist_tls_inventory_full_invariant` that checks
only the four NIST TLS items when they are `full`. It should emit
`CoverageLedgerIssue(code="nist_tls_inventory_full_invariant_failed", ...)`
when:

- a full item lacks `external.tls_inventory` in `evidence.assessment_controls`;
- the control does not use `absence_semantics="control-pass"`;
- required facets are missing;
- no subclaim binds to `external.tls_inventory` with `control-pass` semantics;
- no `safe-probe` evidence kind is present.

- [ ] **Step 2: Call the helper from ledger validation**

Call the helper in `validate_coverage_ledger` so both `coverage validate` and
`coverage reconcile --check` reject inflated NIST TLS `full` claims.

- [ ] **Step 3: Run negative test and verify GREEN for invariant**

Run:

```powershell
uv run --locked pytest tests\test_coverage_ledger.py::test_check_coverage_reconciliation_rejects_full_nist_tls_without_inventory_control -q
```

Expected: PASS.

Add a CLI regression for `coverage validate --ledger broken.yml --format json`
so the user-facing command reports the same guardrail.

### Task 3: Update the Coverage Ledger

**Files:**
- Modify: `src/webconf_audit/data/control_source_coverage.yml`

- [ ] **Step 1: Promote four NIST items**

Set each of the four target items to `status: full`, add
`assessment_controls` for `external.tls_inventory`, and add subclaims with
mandatory bindings.

Use:

```yaml
assessment_controls:
  - control_id: external.tls_inventory
    strength: direct
    origin: declared
    absence_semantics: control-pass
    assessed_facets:
      - negotiated_cipher
```

for cipher posture and preference, and:

```yaml
assessment_controls:
  - control_id: external.tls_inventory
    strength: direct
    origin: declared
    absence_semantics: control-pass
    assessed_facets:
      - ocsp_stapling
```

for OCSP and revocation items.

- [ ] **Step 2: Update NIST summary**

Change NIST expected summary to:

```yaml
applicable: 10
full: 10
partial: 0
policy_review: 0
uncovered: 0
excluded: 0
full_percent: '100.0'
```

### Task 4: Update Reconciliation Baselines and Generated Docs

**Files:**
- Modify: `src/webconf_audit/coverage_ledger.py`
- Modify: `docs/control-source-coverage-tracker.md`
- Modify: `docs/benchmarks-covering.md`
- Modify: `docs/standards-roadmap.md`
- Modify: `tests/test_coverage_ledger.py`

- [ ] **Step 1: Update expected test summaries**

Adjust `test_packaged_ledger_matches_final_reconciled_source_counts` so NIST
expects 10 full and 0 partial.

- [ ] **Step 2: Update reconciliation text**

Replace the follow-up 14 guardrail wording that says NIST TLS rows remain
partial with wording that says those rows are full only through complete
declared TLS inventory evidence.

- [ ] **Step 3: Regenerate coverage docs**

Run:

```powershell
uv run --locked python -m webconf_audit.cli coverage reconcile --write
```

Expected: tracked coverage docs update deterministically.

### Task 5: Verify and Commit

**Files:**
- All files changed by Tasks 1-4

- [ ] **Step 1: Run focused tests**

```powershell
uv run --locked pytest tests\test_coverage_ledger.py tests\test_coverage_cli.py tests\test_release_check_script.py -q
```

- [ ] **Step 2: Run ledger commands**

```powershell
uv run --locked python -m webconf_audit.cli coverage validate
uv run --locked python -m webconf_audit.cli coverage reconcile --check
```

- [ ] **Step 3: Run CI and Docker verification**

```powershell
uv run --locked ruff check .
uv run --locked pytest tests --ignore=tests/integration_external --ignore=tests/integration_local --ignore=tests/integration_rule_coverage --ignore=tests/integration_real_world_cross_mode -q
uv run --locked pytest tests/integration_external tests/integration_local tests/integration_rule_coverage tests/integration_real_world_cross_mode -q
uv run --locked python scripts/release_check.py
```

- [ ] **Step 4: Commit and open PR**

```powershell
git add docs/superpowers src tests docs
git commit -m "Complete NIST TLS inventory coverage evidence"
git push -u origin codex/nist-tls-evidence-completion
gh pr create --base master --head codex/nist-tls-evidence-completion --title "Complete NIST TLS inventory coverage evidence" --body-file <generated-body>
```
