"""Reconcile the temporary Markdown coverage tracker with registry evidence."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from webconf_audit.cli import _ensure_all_rules_loaded
from webconf_audit.rule_registry import registry

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module():
    script = _REPO_ROOT / "scripts" / "crosswalk_docs.py"
    spec = importlib.util.spec_from_file_location("crosswalk_docs_under_test", script)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tracker_claims_use_conservative_followup_01_snapshot() -> None:
    module = _load_module()

    claims = module.load_tracker_claims(_REPO_ROOT)
    by_source: dict[str, list[object]] = {}
    for claim in claims:
        by_source.setdefault(claim.source_id, []).append(claim)

    assert len(by_source["owasp-top10-2025"]) == 8
    assert len(by_source["owasp-asvs-5.0.0"]) == 22
    assert len(by_source["pci-dss-4.0.1"]) == 11

    status_counts = {
        source_id: module.count_claim_statuses(source_claims)
        for source_id, source_claims in by_source.items()
    }
    assert status_counts["owasp-top10-2025"] == {
        "full": 0,
        "partial": 8,
        "policy-review": 0,
        "uncovered": 0,
        "excluded": 0,
    }
    assert status_counts["owasp-asvs-5.0.0"] == {
        "full": 14,
        "partial": 8,
        "policy-review": 0,
        "uncovered": 0,
        "excluded": 0,
    }
    assert status_counts["pci-dss-4.0.1"] == {
        "full": 0,
        "partial": 9,
        "policy-review": 0,
        "uncovered": 2,
        "excluded": 0,
    }


def test_coverage_documents_reconcile_with_registry() -> None:
    module = _load_module()
    _ensure_all_rules_loaded()

    issues = module.validate_coverage_documents(
        _REPO_ROOT,
        registry.list_rules(),
    )

    assert issues == ()
