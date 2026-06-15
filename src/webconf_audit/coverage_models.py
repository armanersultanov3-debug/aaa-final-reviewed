"""Versioned models for control-source coverage claims."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, StringConstraints

Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=160,
        pattern=r"^[a-z0-9][a-z0-9.-]*$",
    ),
]
RuleIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=200,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    ),
]
NonEmptyText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=4096),
]
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
AbsenceSemantics = Literal["none", "facet-pass", "control-pass"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LedgerSnapshot(_StrictModel):
    snapshot_id: Identifier
    effective_date: date
    base_revision: NonEmptyText
    description: NonEmptyText


class CoverageSummary(_StrictModel):
    applicable: int = Field(ge=0)
    full: int = Field(ge=0)
    partial: int = Field(ge=0)
    policy_review: int = Field(ge=0)
    uncovered: int = Field(ge=0)
    excluded: int = Field(ge=0)
    full_percent: Decimal = Field(ge=0, le=100, decimal_places=1)


class ControlReference(_StrictModel):
    standard: NonEmptyText
    reference: NonEmptyText
    grouped_references: tuple[NonEmptyText, ...] = Field(
        default=(),
        max_length=64,
    )


class RegistryReferenceClaim(_StrictModel):
    rule_id: RuleIdentifier
    standard: NonEmptyText
    reference: NonEmptyText
    strength: MappingStrength
    origin: MappingOrigin


class AssessableRuleEvidence(_StrictModel):
    rule_id: RuleIdentifier
    strength: MappingStrength
    origin: MappingOrigin
    absence_semantics: AbsenceSemantics = "none"
    assessed_facets: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)


class AssessableControlEvidence(_StrictModel):
    control_id: RuleIdentifier
    strength: MappingStrength
    origin: MappingOrigin
    absence_semantics: AbsenceSemantics = "none"
    assessed_facets: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)


class CoverageEvidence(_StrictModel):
    rule_ids: tuple[RuleIdentifier, ...] = Field(default=(), max_length=1024)
    registry_references: tuple[RegistryReferenceClaim, ...] = Field(
        default=(),
        max_length=1024,
    )
    assessment_rules: tuple[AssessableRuleEvidence, ...] = Field(
        default=(),
        max_length=1024,
    )
    assessment_controls: tuple[AssessableControlEvidence, ...] = Field(
        default=(),
        max_length=1024,
    )
    evidence_kinds: tuple[EvidenceKind, ...] = Field(default=(), max_length=8)
    rationale: NonEmptyText
    limitations: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)


class Exclusion(_StrictModel):
    reason: NonEmptyText
    boundary: NonEmptyText


class ItemProvenance(_StrictModel):
    reviewed_on: date
    source_url: AnyHttpUrl
    change_ref: NonEmptyText


class CoverageItem(_StrictModel):
    item_id: Identifier
    title: NonEmptyText
    references: tuple[ControlReference, ...] = Field(min_length=1, max_length=64)
    applicability: Applicability
    status: CoverageStatus
    evidence: CoverageEvidence
    exclusion: Exclusion | None = None
    provenance: ItemProvenance


class CoverageSource(_StrictModel):
    source_id: Identifier
    title: NonEmptyText
    version: NonEmptyText
    authority_url: AnyHttpUrl
    scope_note: NonEmptyText
    expected_summary: CoverageSummary
    items: tuple[CoverageItem, ...] = Field(min_length=1, max_length=512)


class CoverageLedger(_StrictModel):
    schema_version: Literal[1]
    snapshot: LedgerSnapshot
    sources: tuple[CoverageSource, ...] = Field(min_length=1, max_length=32)


class CoverageLedgerIssue(_StrictModel):
    code: NonEmptyText
    message: NonEmptyText
    source_id: str | None = None
    item_id: str | None = None
    rule_id: str | None = None
    path: str | None = None


class SourceCoverageSummary(_StrictModel):
    source_id: Identifier
    title: NonEmptyText
    applicable: int = Field(ge=0)
    full: int = Field(ge=0)
    partial: int = Field(ge=0)
    policy_review: int = Field(ge=0)
    uncovered: int = Field(ge=0)
    excluded: int = Field(ge=0)
    full_percent: Decimal = Field(ge=0, le=100, decimal_places=1)


__all__ = [
    "AbsenceSemantics",
    "AssessableControlEvidence",
    "AssessableRuleEvidence",
    "Applicability",
    "ControlReference",
    "CoverageEvidence",
    "CoverageItem",
    "CoverageLedger",
    "CoverageLedgerIssue",
    "CoverageSource",
    "CoverageStatus",
    "CoverageSummary",
    "EvidenceKind",
    "Exclusion",
    "ItemProvenance",
    "LedgerSnapshot",
    "MappingOrigin",
    "MappingStrength",
    "RegistryReferenceClaim",
    "SourceCoverageSummary",
]
