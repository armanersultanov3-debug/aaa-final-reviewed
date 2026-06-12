"""Integrity checks for rule-to-standard crosswalk metadata."""

from __future__ import annotations

import pytest

from webconf_audit.crosswalk_integrity import (
    CountedCoverageClaim,
    CrosswalkIssue,
    validate_registry_crosswalk,
    validate_standard_reference,
)
from webconf_audit.rule_registry import RuleMeta, StandardReference
from webconf_audit.standard_catalog import find_standard_item


def _rule(
    rule_id: str,
    *,
    standards: tuple[StandardReference, ...] = (),
    standards_secondary: tuple[StandardReference, ...] = (),
) -> RuleMeta:
    return RuleMeta(
        rule_id=rule_id,
        title="Test rule",
        severity="low",
        description="Test rule description.",
        recommendation="Test recommendation.",
        category="local",
        server_type="nginx",
        standards=standards,
        standards_secondary=standards_secondary,
    )


def _unsafe_reference(**overrides: object) -> StandardReference:
    """Build an impossible reference to exercise validator accumulation."""
    values: dict[str, object] = {
        "standard": "OWASP Top 10",
        "reference": "A02:2025",
        "url": "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
        "coverage": "direct",
        "note": None,
        "tier": "primary",
        "origin": "derived",
        "derived_from_standard": None,
        "derived_from_reference": None,
    }
    values.update(overrides)
    ref = object.__new__(StandardReference)
    for field_name, value in values.items():
        object.__setattr__(ref, field_name, value)
    return ref


def test_standard_reference_defaults_to_declared_origin() -> None:
    ref = StandardReference(standard="OWASP ASVS", reference="v5.0.0-3.4.2")

    assert ref.origin == "declared"
    assert ref.derived_from_standard is None
    assert ref.derived_from_reference is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "origin": "declared",
            "derived_from_standard": "OWASP Top 10",
            "derived_from_reference": "A05:2021",
        },
        {
            "origin": "derived",
            "tier": "secondary",
        },
        {
            "origin": "derived",
            "tier": "primary",
            "derived_from_standard": "OWASP Top 10",
            "derived_from_reference": "A05:2021",
        },
    ],
)
def test_standard_reference_rejects_impossible_provenance(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="provenance|derived"):
        StandardReference(
            standard="OWASP Top 10",
            reference="A02:2025",
            **kwargs,  # type: ignore[arg-type]
        )


def test_catalog_contains_corrected_counted_references() -> None:
    for standard, reference in (
        ("OWASP ASVS", "v5.0.0-3.3.3"),
        ("OWASP ASVS", "v5.0.0-3.4.2"),
        ("OWASP ASVS", "v5.0.0-3.4.8"),
        ("OWASP Top 10", "A02:2025"),
        ("PCI DSS v4.0.1", "Req. 8.3.5 / 8.3.6"),
    ):
        assert find_standard_item(standard, reference) is not None


def test_validate_standard_reference_reports_unknown_strict_reference() -> None:
    ref = StandardReference(
        standard="OWASP ASVS",
        reference="v5.0.0-99.99.99",
    )

    issues = validate_standard_reference(ref)

    assert [issue.code for issue in issues] == ["unknown_standard_reference"]


def test_validate_standard_reference_accumulates_invalid_provenance() -> None:
    ref = _unsafe_reference()

    issues = validate_standard_reference(ref)

    assert [issue.code for issue in issues] == [
        "derived_reference_in_primary_tier",
        "invalid_mapping_provenance",
    ]


def test_validate_registry_crosswalk_reports_all_issues_in_stable_order() -> None:
    missing_note = StandardReference(
        standard="OWASP ASVS",
        reference="v5.0.0-3.4.2",
        coverage="partial",
    )
    primary = StandardReference(
        standard="OWASP ASVS",
        reference="v5.0.0-3.4.8",
    )
    secondary = StandardReference(
        standard="OWASP ASVS",
        reference="v5.0.0-3.4.8",
        tier="secondary",
    )
    rules = (
        _rule("z.rule", standards=(missing_note,)),
        _rule(
            "a.rule",
            standards=(primary,),
            standards_secondary=(secondary,),
        ),
    )

    issues = validate_registry_crosswalk(rules)

    assert issues == tuple(
        sorted(
            issues,
            key=lambda issue: (
                issue.code,
                issue.rule_id or "",
                issue.standard or "",
                issue.reference or "",
                issue.message,
            ),
        )
    )
    assert {issue.code for issue in issues} == {
        "duplicate_cross_tier_reference",
        "missing_mapping_note",
    }
    assert all(isinstance(issue, CrosswalkIssue) for issue in issues)


def test_derived_reference_cannot_independently_support_full_claim() -> None:
    derived = StandardReference(
        standard="OWASP Top 10",
        reference="A02:2025",
        tier="secondary",
        origin="derived",
        derived_from_standard="OWASP Top 10",
        derived_from_reference="A05:2021",
    )
    claim = CountedCoverageClaim(
        source_id="owasp-top10-2025",
        item_id="A02:2025",
        status="full",
        references=(("OWASP Top 10", "A02:2025"),),
    )

    issues = validate_registry_crosswalk(
        (_rule("test.rule", standards_secondary=(derived,)),),
        coverage_claims=(claim,),
    )

    assert [issue.code for issue in issues] == [
        "coverage_claim_exceeds_evidence",
    ]


def test_partial_claim_without_registry_evidence_reports_mismatch() -> None:
    claim = CountedCoverageClaim(
        source_id="owasp-top10-2025",
        item_id="A03:2025",
        status="partial",
        references=(("OWASP Top 10", "A03:2025"),),
    )

    issues = validate_registry_crosswalk((), coverage_claims=(claim,))

    assert [issue.code for issue in issues] == [
        "coverage_tracker_registry_mismatch",
    ]


def test_full_claim_accepts_declared_direct_evidence() -> None:
    declared = StandardReference(
        standard="OWASP ASVS",
        reference="v5.0.0-3.4.4",
    )
    claim = CountedCoverageClaim(
        source_id="owasp-asvs-5.0.0",
        item_id="v5.0.0-3.4.4",
        status="full",
        references=(("OWASP ASVS", "v5.0.0-3.4.4"),),
    )

    assert validate_registry_crosswalk(
        (_rule("test.rule", standards=(declared,)),),
        coverage_claims=(claim,),
    ) == ()
