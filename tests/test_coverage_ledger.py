"""Tests for the versioned machine-readable coverage ledger."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import date
from decimal import Decimal
import os
from pathlib import Path

import pytest
import yaml

from webconf_audit.coverage_ledger import (
    CoverageLedgerLoadError,
    check_coverage_reconciliation,
    check_coverage_documentation,
    load_coverage_ledger,
    reconcile_coverage_documents,
    render_coverage_markdown,
    render_coverage_json,
    summarize_coverage,
    validate_coverage_ledger,
    write_coverage_reconciliation,
    write_coverage_output,
)
from webconf_audit.coverage_models import CoverageLedger, CoverageReconciliation
from webconf_audit.rule_registry import RuleMeta, RuleRegistry, StandardReference
from webconf_audit.standard_catalog import is_valid_ledger_reference


def _ledger_payload(
    *,
    status: str = "full",
    applicability: str = "applicable",
    evidence: dict[str, object] | None = None,
    exclusion: dict[str, str] | None = None,
) -> dict[str, object]:
    if evidence is None:
        evidence = {
            "rule_ids": ["test.rule"],
            "registry_references": [
                {
                    "rule_id": "test.rule",
                    "standard": "OWASP ASVS",
                    "reference": "v5.0.0-3.4.1",
                    "strength": "direct",
                    "origin": "declared",
                }
            ],
            "evidence_kinds": ["safe-probe"],
            "rationale": "The test rule provides bounded evidence.",
            "limitations": [],
        }
    counts = {
        "full": 0,
        "partial": 0,
        "policy_review": 0,
        "uncovered": 0,
        "excluded": 0,
    }
    counts["policy_review" if status == "policy-review" else status] = 1
    applicable = 0 if status == "excluded" else 1
    return {
        "schema_version": 1,
        "snapshot": {
            "snapshot_id": "test-snapshot",
            "effective_date": "2026-06-12",
            "base_revision": "424bc51",
            "description": "Test ledger snapshot.",
        },
        "sources": [
            {
                "source_id": "owasp-asvs-5.0.0",
                "title": "OWASP ASVS v5.0.0",
                "version": "5.0.0",
                "authority_url": (
                    "https://github.com/OWASP/ASVS/blob/master/5.0/en/"
                    "0x12-V3-Web-Frontend-Security.md"
                ),
                "scope_note": "Selected web requirements.",
                "expected_summary": {
                    "applicable": applicable,
                    **counts,
                    "full_percent": "100.0" if status == "full" else "0.0",
                },
                "items": [
                    {
                        "item_id": "asvs-hsts",
                        "title": "HTTP Strict Transport Security",
                        "references": [
                            {
                                "standard": "OWASP ASVS",
                                "reference": "v5.0.0-3.4.1",
                                "grouped_references": [],
                            }
                        ],
                        "applicability": applicability,
                        "status": status,
                        "evidence": evidence,
                        "exclusion": exclusion,
                        "provenance": {
                            "reviewed_on": "2026-06-12",
                            "source_url": "https://github.com/OWASP/ASVS",
                            "change_ref": "followup-02",
                        },
                    }
                ],
            }
        ],
    }


def _registry(*, derived: bool = False, policy_review: bool = False) -> RuleRegistry:
    registry = RuleRegistry()
    ref = StandardReference(
        standard="OWASP ASVS",
        reference="v5.0.0-3.4.1",
        tier="secondary" if derived else "primary",
        origin="derived" if derived else "declared",
        derived_from_standard="OWASP Top 10" if derived else None,
        derived_from_reference="A05:2021" if derived else None,
    )
    registry.register_meta(
        RuleMeta(
            rule_id="test.rule",
            title="Test rule",
            severity="low",
            description="Test description.",
            recommendation="Test recommendation.",
            category="external",
            input_kind="probe",
            tags=("policy-review",) if policy_review else (),
            standards_secondary=(ref,) if derived else (),
            standards=(ref,) if not derived else (),
        )
    )
    return registry


def test_coverage_ledger_rejects_unknown_fields() -> None:
    payload = _ledger_payload()
    payload["unexpected"] = True

    with pytest.raises(ValueError, match="unexpected"):
        CoverageLedger.model_validate(payload)


def test_coverage_ledger_accepts_real_rule_id_shape() -> None:
    payload = _ledger_payload()
    payload["sources"][0]["items"][0]["evidence"]["rule_ids"] = [  # type: ignore[index]
        "external.hsts_header_missing"
    ]
    payload["sources"][0]["items"][0]["evidence"]["registry_references"][0][  # type: ignore[index]
        "rule_id"
    ] = "external.hsts_header_missing"

    ledger = CoverageLedger.model_validate(payload)

    assert (
        ledger.sources[0].items[0].evidence.rule_ids
        == ("external.hsts_header_missing",)
    )


def test_load_coverage_ledger_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CoverageLedgerLoadError) as exc_info:
        load_coverage_ledger(tmp_path / "missing.yml")

    assert exc_info.value.issue.code == "ledger_file_not_found"


def test_load_coverage_ledger_rejects_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "large.yml"
    path.write_bytes(b"x" * 1025)

    with pytest.raises(CoverageLedgerLoadError) as exc_info:
        load_coverage_ledger(path, max_bytes=1024)

    assert exc_info.value.issue.code == "ledger_file_too_large"


@pytest.mark.parametrize(
    "content",
    [
        "schema_version: !!python/object/apply:os.system ['echo unsafe']\n",
        "defaults: &defaults\n  status: full\nitem:\n  <<: *defaults\n",
        "item: *missing\n",
    ],
)
def test_load_coverage_ledger_rejects_unsafe_yaml(
    tmp_path: Path,
    content: str,
) -> None:
    path = tmp_path / "unsafe.yml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(CoverageLedgerLoadError) as exc_info:
        load_coverage_ledger(path)

    assert exc_info.value.issue.code == "ledger_yaml_invalid"


def test_load_coverage_ledger_rejects_duplicate_mapping_keys(
    tmp_path: Path,
) -> None:
    path = tmp_path / "duplicate.yml"
    path.write_text(
        "schema_version: 1\nschema_version: 2\n",
        encoding="utf-8",
    )

    with pytest.raises(CoverageLedgerLoadError) as exc_info:
        load_coverage_ledger(path)

    assert exc_info.value.issue.code == "ledger_yaml_invalid"
    assert "duplicate" in exc_info.value.issue.message.lower()


def test_load_coverage_ledger_wraps_schema_errors(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yml"
    payload = _ledger_payload()
    payload["schema_version"] = 2
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(CoverageLedgerLoadError) as exc_info:
        load_coverage_ledger(path)

    assert exc_info.value.issue.code == "ledger_schema_unsupported"


@pytest.mark.parametrize(
    ("source_id", "standard", "known_reference", "unknown_reference"),
    [
        (
            "cis-nginx-3.0.0",
            "CIS",
            "NGINX v3.0.0 §4.1.12",
            "NGINX v3.0.0 §99.1",
        ),
        (
            "cis-apache-http-server-2.4-2.3.0",
            "CIS",
            "Apache HTTP Server 2.4 v2.3.0 §7.2",
            "Apache HTTP Server 2.4 v2.3.0 §99.1",
        ),
        (
            "cis-microsoft-iis-10-1.2.1",
            "CIS",
            "Microsoft IIS 10 v1.2.1 §6.1 / §6.2",
            "Microsoft IIS 10 v1.2.1 §99.1",
        ),
        (
            "nist-sp-800-52r2",
            "NIST SP 800-52 Rev. 2",
            "4.3",
            "99.1",
        ),
        (
            "iso-iec-27002-2022",
            "ISO/IEC 27002:2022",
            "8.27",
            "99.1",
        ),
    ],
)
def test_source_catalog_accepts_only_selected_ledger_references(
    source_id: str,
    standard: str,
    known_reference: str,
    unknown_reference: str,
) -> None:
    assert is_valid_ledger_reference(source_id, standard, known_reference)
    assert not is_valid_ledger_reference(
        source_id,
        standard,
        unknown_reference,
    )


def test_validate_coverage_ledger_accepts_declared_full_evidence() -> None:
    ledger = CoverageLedger.model_validate(_ledger_payload())

    assert validate_coverage_ledger(ledger, _registry()) == ()


def test_validate_coverage_ledger_rejects_derived_only_full_evidence() -> None:
    payload = _ledger_payload()
    evidence = payload["sources"][0]["items"][0]["evidence"]  # type: ignore[index]
    evidence["registry_references"][0]["origin"] = "derived"  # type: ignore[index]
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, _registry(derived=True))

    assert {issue.code for issue in issues} == {
        "derived_reference_used_for_full",
        "insufficient_full_evidence",
    }


def test_validate_coverage_ledger_allows_supplementary_derived_full_evidence() -> None:
    payload = _ledger_payload()
    payload["sources"][0]["items"][0]["references"].append(  # type: ignore[index]
        {
            "standard": "OWASP ASVS",
            "reference": "v5.0.0-3.4.2",
            "grouped_references": [],
        }
    )
    evidence = payload["sources"][0]["items"][0]["evidence"]  # type: ignore[index]
    evidence["registry_references"].append(  # type: ignore[union-attr]
        {
            "rule_id": "test.rule",
            "standard": "OWASP ASVS",
            "reference": "v5.0.0-3.4.2",
            "strength": "direct",
            "origin": "derived",
        }
    )
    registry = _registry()
    meta = registry.get_meta("test.rule")
    assert meta is not None
    derived = StandardReference(
        standard="OWASP ASVS",
        reference="v5.0.0-3.4.2",
        tier="secondary",
        origin="derived",
        derived_from_standard="OWASP Top 10",
        derived_from_reference="A05:2021",
    )
    registry = RuleRegistry()
    registry.register_meta(
        replace(meta, standards_secondary=(derived,))
    )
    ledger = CoverageLedger.model_validate(payload)

    assert validate_coverage_ledger(ledger, registry) == ()


def test_validate_coverage_ledger_rejects_registry_only_full_evidence() -> None:
    payload = _ledger_payload()
    payload["sources"][0]["items"][0]["evidence"]["evidence_kinds"] = [  # type: ignore[index]
        "registry-export"
    ]
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, _registry())

    assert [issue.code for issue in issues] == ["insufficient_full_evidence"]


def test_validate_coverage_ledger_rejects_secondary_only_full_evidence() -> None:
    ledger = CoverageLedger.model_validate(_ledger_payload())
    registry = RuleRegistry()
    registry.register_meta(
        RuleMeta(
            rule_id="test.rule",
            title="Test rule",
            severity="low",
            description="Test description.",
            recommendation="Test recommendation.",
            category="external",
            input_kind="probe",
            standards_secondary=(
                StandardReference(
                    standard="OWASP ASVS",
                    reference="v5.0.0-3.4.1",
                    tier="secondary",
                ),
            ),
        )
    )

    issues = validate_coverage_ledger(ledger, registry)

    assert [issue.code for issue in issues] == ["insufficient_full_evidence"]


def test_validate_coverage_ledger_rejects_duplicate_item_ids_across_sources() -> None:
    payload = _ledger_payload()
    duplicate_source = deepcopy(payload["sources"][0])  # type: ignore[index]
    duplicate_source["source_id"] = "owasp-top10-2025"
    duplicate_source["title"] = "OWASP Top 10:2025"
    duplicate_source["version"] = "2025"
    duplicate_source["authority_url"] = "https://owasp.org/Top10/2025/"
    payload["sources"].append(duplicate_source)  # type: ignore[union-attr]
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, _registry())

    assert "duplicate_item_id" in {issue.code for issue in issues}


def test_validate_coverage_ledger_rejects_unrelated_direct_full_claim() -> None:
    payload = _ledger_payload()
    claim = payload["sources"][0]["items"][0]["evidence"][  # type: ignore[index]
        "registry_references"
    ][0]
    claim["reference"] = "v5.0.0-3.4.4"
    registry = RuleRegistry()
    registry.register_meta(
        RuleMeta(
            rule_id="test.rule",
            title="Test rule",
            severity="low",
            description="Test description.",
            recommendation="Test recommendation.",
            category="external",
            input_kind="probe",
            standards=(
                StandardReference(
                    standard="OWASP ASVS",
                    reference="v5.0.0-3.4.4",
                ),
            ),
        )
    )
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, registry)

    assert "insufficient_full_evidence" in {issue.code for issue in issues}


def test_validate_coverage_ledger_rejects_unlisted_registry_claim_rule() -> None:
    payload = _ledger_payload()
    payload["sources"][0]["items"][0]["evidence"]["rule_ids"] = []  # type: ignore[index]
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, _registry())

    assert [issue.code for issue in issues] == ["registry_reference_mismatch"]


def test_validate_coverage_ledger_rejects_unknown_grouped_reference() -> None:
    payload = _ledger_payload()
    reference = payload["sources"][0]["items"][0]["references"][0]  # type: ignore[index]
    reference["grouped_references"] = ["v5.0.0-3.4.1", "v5.0.0-99.99.99"]
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, _registry())

    assert [issue.code for issue in issues] == ["unknown_source_reference"]


@pytest.mark.parametrize(
    ("status", "applicability", "exclusion"),
    [
        ("excluded", "applicable", {"reason": "Outside scope.", "boundary": "OS"}),
        ("excluded", "excluded", None),
        ("full", "applicable", {"reason": "Outside scope.", "boundary": "OS"}),
    ],
)
def test_validate_coverage_ledger_rejects_invalid_status_applicability(
    status: str,
    applicability: str,
    exclusion: dict[str, str] | None,
) -> None:
    payload = _ledger_payload(
        status=status,
        applicability=applicability,
        evidence={
            "rule_ids": [],
            "registry_references": [],
            "evidence_kinds": [],
            "rationale": "Boundary test.",
            "limitations": [],
        },
        exclusion=exclusion,
    )
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, RuleRegistry())

    assert any(
        issue.code in {
            "invalid_status_applicability",
            "missing_exclusion_reason",
            "unexpected_exclusion",
        }
        for issue in issues
    )


def test_validate_coverage_ledger_rejects_partial_without_limitation() -> None:
    payload = _ledger_payload(
        status="partial",
        evidence={
            "rule_ids": ["test.rule"],
            "registry_references": [
                {
                    "rule_id": "test.rule",
                    "standard": "OWASP ASVS",
                    "reference": "v5.0.0-3.4.1",
                    "strength": "direct",
                    "origin": "declared",
                }
            ],
            "evidence_kinds": ["safe-probe"],
            "rationale": "A narrower signal is implemented.",
            "limitations": [],
        },
    )
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, _registry())

    assert [issue.code for issue in issues] == ["insufficient_partial_evidence"]


def test_validate_coverage_ledger_rejects_partial_without_matching_claim() -> None:
    payload = _ledger_payload(
        status="partial",
        evidence={
            "rule_ids": ["test.rule"],
            "registry_references": [],
            "evidence_kinds": ["safe-probe"],
            "rationale": "A narrower signal is implemented.",
            "limitations": ["The complete requirement is not proven."],
        },
    )
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, _registry())

    assert {issue.code for issue in issues} == {
        "insufficient_partial_evidence",
        "registry_reference_missing",
    }


def test_validate_coverage_ledger_rejects_uncovered_positive_evidence() -> None:
    payload = _ledger_payload(status="uncovered")
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, _registry())

    assert "uncovered_item_has_positive_evidence" in {
        issue.code for issue in issues
    }


def test_validate_coverage_ledger_rejects_bad_summary() -> None:
    payload = _ledger_payload()
    payload["sources"][0]["expected_summary"]["full"] = 0  # type: ignore[index]
    ledger = CoverageLedger.model_validate(payload)

    issues = validate_coverage_ledger(ledger, _registry())

    assert [issue.code for issue in issues] == ["summary_count_mismatch"]


def test_summarize_coverage_uses_decimal_round_half_up() -> None:
    payload = _ledger_payload()
    source = payload["sources"][0]  # type: ignore[index]
    source["items"] = [
        deepcopy(source["items"][0])  # type: ignore[index]
        for _ in range(3)
    ]
    for index, item in enumerate(source["items"]):  # type: ignore[index]
        item["item_id"] = f"item-{index}"
        if index:
            item["status"] = "partial"
            item["evidence"]["limitations"] = ["Narrow signal only."]
    source["expected_summary"] = {
        "applicable": 3,
        "full": 1,
        "partial": 2,
        "policy_review": 0,
        "uncovered": 0,
        "excluded": 0,
        "full_percent": "33.3",
    }
    ledger = CoverageLedger.model_validate(payload)

    summary = summarize_coverage(ledger)[0]

    assert summary.full_percent == Decimal("33.3")


def test_render_coverage_json_is_deterministic() -> None:
    ledger = CoverageLedger.model_validate(_ledger_payload())

    first = render_coverage_json(ledger)
    second = render_coverage_json(ledger)

    assert first == second
    assert '"schema_version": 1' in first
    assert date.fromisoformat("2026-06-12").isoformat() in first


def test_render_coverage_markdown_is_deterministic_and_escapes_tables() -> None:
    payload = _ledger_payload()
    payload["sources"][0]["items"][0]["evidence"]["rationale"] = (  # type: ignore[index]
        "Header A | Header B\nObserved."
    )
    ledger = CoverageLedger.model_validate(payload)

    first = render_coverage_markdown(ledger)
    second = render_coverage_markdown(ledger)

    assert first == second
    assert first.startswith("<!-- Generated from ")
    assert "| OWASP ASVS v5.0.0 | 1 | 1 | 0 | 0 | 0 | 100.0% |" in first
    assert "Header A \\| Header B<br>Observed." in first


def test_coverage_ledger_rejects_implemented_subclaim_without_binding() -> None:
    payload = _ledger_payload()
    payload["sources"][0]["items"][0]["subclaims"] = [  # type: ignore[index]
        {
            "subclaim_id": "asvs-hsts-complete",
            "title": "All mandatory HSTS evidence is implemented.",
            "mandatory": True,
            "implemented": True,
            "bindings": [],
            "limitations": [],
        }
    ]

    with pytest.raises(ValueError, match="Implemented subclaims require at least one binding"):
        CoverageLedger.model_validate(payload)


def test_packaged_ledger_splits_apache_authorization_sections() -> None:
    ledger = load_coverage_ledger()
    apache_source = next(
        source
        for source in ledger.sources
        if source.source_id == "cis-apache-http-server-2.4-2.3.0"
    )
    items = {item.item_id: item for item in apache_source.items}

    assert "apache-4.1-authorization-posture" not in items
    assert "apache-4.1-os-root-access-denied" in items
    assert "apache-4.2-web-content-access" in items
    assert items["apache-4.2-web-content-access"].status == "partial"
    assert any(
        "deployment" in limitation.lower() or "application" in limitation.lower()
        for limitation in items["apache-4.2-web-content-access"].evidence.limitations
    )


def test_packaged_ledger_matches_final_reconciled_source_counts() -> None:
    summaries = {
        summary.source_id: summary.model_dump(mode="json")
        for summary in summarize_coverage(load_coverage_ledger())
    }

    assert summaries == {
        "cis-nginx-3.0.0": {
            "source_id": "cis-nginx-3.0.0",
            "title": "CIS NGINX Benchmark v3.0.0",
            "applicable": 15,
            "full": 8,
            "partial": 6,
            "policy_review": 1,
            "uncovered": 0,
            "excluded": 0,
            "full_percent": "53.3",
        },
        "cis-apache-http-server-2.4-2.3.0": {
            "source_id": "cis-apache-http-server-2.4-2.3.0",
            "title": "CIS Apache HTTP Server 2.4 Benchmark v2.3.0",
            "applicable": 20,
            "full": 19,
            "partial": 1,
            "policy_review": 0,
            "uncovered": 0,
            "excluded": 0,
            "full_percent": "95.0",
        },
        "cis-microsoft-iis-10-1.2.1": {
            "source_id": "cis-microsoft-iis-10-1.2.1",
            "title": "CIS Microsoft IIS 10 Benchmark v1.2.1",
            "applicable": 10,
            "full": 9,
            "partial": 0,
            "policy_review": 0,
            "uncovered": 1,
            "excluded": 0,
            "full_percent": "90.0",
        },
        "owasp-top10-2025": {
            "source_id": "owasp-top10-2025",
            "title": "OWASP Top 10:2025",
            "applicable": 8,
            "full": 0,
            "partial": 8,
            "policy_review": 0,
            "uncovered": 0,
            "excluded": 2,
            "full_percent": "0.0",
        },
        "owasp-asvs-5.0.0": {
            "source_id": "owasp-asvs-5.0.0",
            "title": "OWASP ASVS v5.0.0",
            "applicable": 22,
            "full": 14,
            "partial": 8,
            "policy_review": 0,
            "uncovered": 0,
            "excluded": 0,
            "full_percent": "63.6",
        },
        "nist-sp-800-52r2": {
            "source_id": "nist-sp-800-52r2",
            "title": "NIST SP 800-52 Rev. 2",
            "applicable": 10,
            "full": 6,
            "partial": 4,
            "policy_review": 0,
            "uncovered": 0,
            "excluded": 0,
            "full_percent": "60.0",
        },
        "pci-dss-4.0.1": {
            "source_id": "pci-dss-4.0.1",
            "title": "PCI DSS v4.0.1",
            "applicable": 11,
            "full": 0,
            "partial": 9,
            "policy_review": 0,
            "uncovered": 2,
            "excluded": 2,
            "full_percent": "0.0",
        },
        "iso-iec-27002-2022": {
            "source_id": "iso-iec-27002-2022",
            "title": "ISO/IEC 27002:2022",
            "applicable": 10,
            "full": 8,
            "partial": 2,
            "policy_review": 0,
            "uncovered": 0,
            "excluded": 0,
            "full_percent": "80.0",
        },
    }


def test_check_coverage_reconciliation_requires_frozen_accepted_revisions() -> None:
    from webconf_audit.cli import _ensure_all_rules_loaded
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    ledger = load_coverage_ledger()
    snapshot = ledger.snapshot.model_copy(
        update={"accepted_revisions": ledger.snapshot.accepted_revisions[:-1]}
    )

    issues = check_coverage_reconciliation(
        ledger.model_copy(update={"snapshot": snapshot}),
        registry,
        compare_tracked=False,
    )

    assert "accepted_revisions_missing" in {issue.code for issue in issues}


def test_validate_coverage_ledger_requires_denominator_reason_for_program_delta() -> None:
    from webconf_audit.cli import _ensure_all_rules_loaded
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    ledger = load_coverage_ledger()
    sources = []
    for source in ledger.sources:
        if source.source_id == "cis-apache-http-server-2.4-2.3.0":
            source = source.model_copy(update={"denominator_notes": ()})
        sources.append(source)

    issues = validate_coverage_ledger(
        ledger.model_copy(update={"sources": tuple(sources)}),
        registry,
    )

    assert "missing_denominator_change_reason" in {issue.code for issue in issues}


def test_reconcile_coverage_documents_renders_final_deltas() -> None:
    from webconf_audit.cli import _ensure_all_rules_loaded
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    reconciliation = reconcile_coverage_documents(load_coverage_ledger(), registry)

    assert isinstance(reconciliation, CoverageReconciliation)
    assert len(reconciliation.artifacts) == 3
    assert "## Final Counted Coverage Reconciliation (2026-06-16)" in next(
        artifact.content
        for artifact in reconciliation.artifacts
        if artifact.label == "standards-roadmap-final-reconciliation"
    )
    nist = next(
        source
        for source in reconciliation.sources
        if source.source_id == "nist-sp-800-52r2"
    )
    assert nist.baseline.full == 10
    assert nist.current.full == 6
    assert nist.delta.full == -4
    assert any(
        item.item_id == "apache-2.1-module-minimization"
        and item.from_status == "partial"
        and item.to_status == "full"
        for source in reconciliation.sources
        for item in source.changed_items
    )


def test_packaged_ledger_keeps_iis_ftp_uncovered_and_unbound() -> None:
    ledger = load_coverage_ledger()
    source = next(
        entry
        for entry in ledger.sources
        if entry.source_id == "cis-microsoft-iis-10-1.2.1"
    )
    item = next(
        entry
        for entry in source.items
        if entry.item_id == "iis-6.1-ftp-encryption-logon-restrictions"
    )

    assert item.applicability == "applicable"
    assert item.status == "uncovered"
    assert item.evidence.rule_ids == ()
    assert item.evidence.assessment_rules == ()
    assert item.evidence.assessment_controls == ()


def test_check_coverage_reconciliation_detects_prohibited_language(
    tmp_path: Path,
) -> None:
    from webconf_audit.cli import _ensure_all_rules_loaded
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    repo_root = Path(__file__).resolve().parents[1]
    (tmp_path / "docs").mkdir()
    for relative in (
        "README.md",
        "docs/architecture.md",
        "docs/benchmarks-covering.md",
        "docs/control-source-coverage-tracker.md",
        "docs/standards-roadmap.md",
    ):
        source = repo_root / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    benchmark = tmp_path / "docs" / "benchmarks-covering.md"
    benchmark.write_text(
        benchmark.read_text(encoding="utf-8").replace(
            "does not certify CIS, OWASP, ASVS, NIST, PCI DSS, or ISO compliance.",
            "the project is NIST compliant.",
        ),
        encoding="utf-8",
    )

    issues = check_coverage_reconciliation(
        load_coverage_ledger(),
        registry,
        repo_root=tmp_path,
    )

    assert "prohibited_compliance_language" in {issue.code for issue in issues}


def test_check_coverage_documentation_detects_tracker_and_summary_drift(
    tmp_path: Path,
) -> None:
    ledger = CoverageLedger.model_validate(_ledger_payload())
    tracker = tmp_path / "tracker.md"
    benchmark = tmp_path / "benchmark.md"
    tracker.write_text("stale\n", encoding="utf-8")
    benchmark.write_text(
        "\n".join(
            [
                "| Control source | Applicable | Full | Partial | `policy-review` | Uncovered | Full coverage |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
                "| OWASP ASVS v5.0.0 | 1 | 0 | 1 | 0 | 0 | 0.0% |",
            ]
        ),
        encoding="utf-8",
    )

    issues = check_coverage_documentation(ledger, tracker, benchmark)

    assert {issue.code for issue in issues} == {
        "benchmark_summary_drift",
        "tracker_render_drift",
    }


def test_check_coverage_documentation_detects_extra_benchmark_source(
    tmp_path: Path,
) -> None:
    ledger = CoverageLedger.model_validate(_ledger_payload())
    tracker = tmp_path / "tracker.md"
    benchmark = tmp_path / "benchmark.md"
    tracker.write_text(render_coverage_markdown(ledger), encoding="utf-8")
    benchmark.write_text(
        "\n".join(
            [
                "| Control source | Applicable | Full | Partial | `policy-review` | Uncovered | Full coverage |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
                "| OWASP ASVS v5.0.0 | 1 | 1 | 0 | 0 | 0 | 100.0% |",
                "| Removed source | 1 | 1 | 0 | 0 | 0 | 100.0% |",
            ]
        ),
        encoding="utf-8",
    )

    issues = check_coverage_documentation(ledger, tracker, benchmark)

    assert [issue.code for issue in issues] == ["benchmark_summary_drift"]
    assert "Removed source" in issues[0].message


def test_write_coverage_reconciliation_rolls_back_on_replace_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    first = tmp_path / "first.md"
    second = tmp_path / "second.md"
    first.write_text("first-old\n", encoding="utf-8")
    second.write_text("second-old\n", encoding="utf-8")
    reconciliation = CoverageReconciliation(
        sources=(
            reconcile_coverage_documents(  # type: ignore[arg-type]
                load_coverage_ledger(),
                _registry(),
                repo_root=Path(__file__).resolve().parents[1],
            ).sources[0],
        ),
        artifacts=(
            {
                "label": "first-artifact",
                "path": str(first),
                "content": "first-new\n",
            },
            {
                "label": "second-artifact",
                "path": str(second),
                "content": "second-new\n",
            },
        ),
    )
    real_replace = os.replace
    calls = {"count": 0}

    def failing_replace(src, dst):
        calls["count"] += 1
        if calls["count"] == 4:
            raise OSError("simulated publish failure")
        return real_replace(src, dst)

    monkeypatch.setattr("webconf_audit.coverage_ledger.os.replace", failing_replace)

    issues = write_coverage_reconciliation(reconciliation)

    assert [issue.code for issue in issues] == ["reconciliation_write_failed"]
    assert first.read_text(encoding="utf-8") == "first-old\n"
    assert second.read_text(encoding="utf-8") == "second-old\n"


def test_write_coverage_reconciliation_reports_cross_drive_staging_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = reconcile_coverage_documents(  # type: ignore[arg-type]
        load_coverage_ledger(),
        _registry(),
        repo_root=Path(__file__).resolve().parents[1],
    ).sources[0]
    reconciliation = CoverageReconciliation(
        sources=(source,),
        artifacts=(
            {
                "label": "first-artifact",
                "path": str(tmp_path / "first.md"),
                "content": "first-new\n",
            },
            {
                "label": "second-artifact",
                "path": str(tmp_path / "second.md"),
                "content": "second-new\n",
            },
        ),
    )

    def fail_commonpath(paths: list[str]) -> str:
        raise ValueError("Paths don't have the same drive")

    monkeypatch.setattr("webconf_audit.coverage_ledger.os.path.commonpath", fail_commonpath)

    issues = write_coverage_reconciliation(reconciliation)

    assert [issue.code for issue in issues] == ["reconciliation_write_failed"]
    assert "different drives" in issues[0].message


def test_write_coverage_output_refuses_existing_file(tmp_path: Path) -> None:
    output = tmp_path / "coverage.json"
    output.write_text("original", encoding="utf-8")

    issue = write_coverage_output(output, "replacement", force=False)

    assert issue is not None
    assert issue.code == "output_exists"
    assert output.read_text(encoding="utf-8") == "original"


def test_write_coverage_output_replaces_existing_file_with_force(
    tmp_path: Path,
) -> None:
    output = tmp_path / "coverage.json"
    output.write_text("original", encoding="utf-8")

    issue = write_coverage_output(output, "replacement\n", force=True)

    assert issue is None
    assert output.read_text(encoding="utf-8") == "replacement\n"


def test_write_coverage_output_refuses_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("target", encoding="utf-8")
    output = tmp_path / "coverage.json"
    try:
        output.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is unavailable in this environment.")

    issue = write_coverage_output(output, "replacement", force=True)

    assert issue is not None
    assert issue.code == "output_write_failed"
    assert target.read_text(encoding="utf-8") == "target"
