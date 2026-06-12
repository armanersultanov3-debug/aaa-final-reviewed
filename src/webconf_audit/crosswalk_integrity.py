"""Deterministic, offline validation for rule-to-standard crosswalks."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Literal

from webconf_audit.rule_registry import RuleMeta, StandardReference
from webconf_audit.standard_catalog import (
    STRICT_CATALOG_STANDARDS,
    StandardSourceId,
    find_standard_item,
)

CoverageClaimStatus = Literal[
    "full",
    "partial",
    "policy-review",
    "uncovered",
    "excluded",
]


@dataclass(frozen=True)
class CountedCoverageClaim:
    """Versioned temporary representation of one Markdown tracker row."""

    source_id: StandardSourceId
    item_id: str
    status: CoverageClaimStatus
    references: tuple[tuple[str, str], ...]
    schema_version: Literal[1] = 1

    def __post_init__(self) -> None:
        if not self.item_id.strip():
            raise ValueError("Coverage claim item_id must be non-empty.")
        if not self.references:
            raise ValueError("Coverage claim must identify at least one reference.")


@dataclass(frozen=True)
class CrosswalkIssue:
    code: str
    rule_id: str | None
    standard: str | None
    reference: str | None
    message: str


def _issue_sort_key(issue: CrosswalkIssue) -> tuple[str, str, str, str, str]:
    return (
        issue.code,
        issue.rule_id or "",
        issue.standard or "",
        issue.reference or "",
        issue.message,
    )


def validate_standard_reference(
    ref: StandardReference,
) -> tuple[CrosswalkIssue, ...]:
    """Validate one reference without performing network access."""
    issues: list[CrosswalkIssue] = []
    origin = getattr(ref, "origin", None)
    derived_standard = getattr(ref, "derived_from_standard", None)
    derived_reference = getattr(ref, "derived_from_reference", None)

    provenance_valid = False
    if origin == "declared":
        provenance_valid = derived_standard is None and derived_reference is None
    elif origin == "derived":
        provenance_valid = bool(derived_standard) and bool(derived_reference)
    if not provenance_valid:
        issues.append(
            CrosswalkIssue(
                code="invalid_mapping_provenance",
                rule_id=None,
                standard=ref.standard,
                reference=ref.reference,
                message="Mapping origin and derivation source are inconsistent.",
            )
        )

    if origin == "derived" and ref.tier != "secondary":
        issues.append(
            CrosswalkIssue(
                code="derived_reference_in_primary_tier",
                rule_id=None,
                standard=ref.standard,
                reference=ref.reference,
                message="Derived references must use the secondary tier.",
            )
        )

    if (
        ref.standard in STRICT_CATALOG_STANDARDS
        and find_standard_item(ref.standard, ref.reference) is None
    ):
        issues.append(
            CrosswalkIssue(
                code="unknown_standard_reference",
                rule_id=None,
                standard=ref.standard,
                reference=ref.reference,
                message="Reference is not present in the canonical project catalog.",
            )
        )

    if (
        ref.standard in STRICT_CATALOG_STANDARDS
        and ref.coverage in {"partial", "related"}
        and not (ref.note or "").strip()
    ):
        issues.append(
            CrosswalkIssue(
                code="missing_mapping_note",
                rule_id=None,
                standard=ref.standard,
                reference=ref.reference,
                message=f"{ref.coverage.title()} mappings require a bounded evidence note.",
            )
        )

    return tuple(sorted(set(issues), key=_issue_sort_key))


def validate_registry_crosswalk(
    rules: Iterable[RuleMeta],
    *,
    coverage_claims: Iterable[CountedCoverageClaim] = (),
) -> tuple[CrosswalkIssue, ...]:
    """Return all registry crosswalk defects in stable order."""
    rule_list = tuple(rules)
    issues: list[CrosswalkIssue] = []
    evidence: dict[tuple[str, str], list[StandardReference]] = {}
    for meta in rule_list:
        for ref in (*meta.standards, *meta.standards_secondary):
            evidence.setdefault((ref.standard, ref.reference), []).append(ref)
            issues.extend(
                replace(issue, rule_id=meta.rule_id)
                for issue in validate_standard_reference(ref)
            )

        primary = {(ref.standard, ref.reference) for ref in meta.standards}
        secondary = {
            (ref.standard, ref.reference)
            for ref in meta.standards_secondary
        }
        for standard, reference in sorted(primary & secondary):
            issues.append(
                CrosswalkIssue(
                    code="duplicate_cross_tier_reference",
                    rule_id=meta.rule_id,
                    standard=standard,
                    reference=reference,
                    message="The same standard reference appears in both tiers.",
                )
            )

    for claim in coverage_claims:
        for standard, reference in claim.references:
            matching = evidence.get((standard, reference), [])
            if claim.status in {"partial", "policy-review"} and not matching:
                issues.append(
                    CrosswalkIssue(
                        code="coverage_tracker_registry_mismatch",
                        rule_id=None,
                        standard=standard,
                        reference=reference,
                        message=(
                            f"Counted {claim.status} item {claim.item_id!r} has "
                            "no matching registry evidence."
                        ),
                    )
                )
            if claim.status == "full" and not any(
                ref.origin == "declared" and ref.coverage == "direct"
                for ref in matching
            ):
                issues.append(
                    CrosswalkIssue(
                        code="coverage_claim_exceeds_evidence",
                        rule_id=None,
                        standard=standard,
                        reference=reference,
                        message=(
                            f"Counted full item {claim.item_id!r} lacks a "
                            "declared direct registry reference."
                        ),
                    )
                )

    return tuple(sorted(set(issues), key=_issue_sort_key))


__all__ = [
    "CountedCoverageClaim",
    "CoverageClaimStatus",
    "CrosswalkIssue",
    "validate_registry_crosswalk",
    "validate_standard_reference",
]
