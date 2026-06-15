"""Versioned models for control-source coverage claims."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

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
    accepted_revisions: tuple["AcceptedProgramRevision", ...] = Field(
        default=(),
        max_length=32,
    )


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


class AcceptedProgramRevision(_StrictModel):
    step_id: Identifier
    merge_sha: NonEmptyText
    summary: NonEmptyText


class CoverageSubclaimBinding(_StrictModel):
    kind: Literal["rule", "control", "evidence-kind"]
    target: NonEmptyText
    strength: MappingStrength | None = None
    origin: MappingOrigin | None = None
    absence_semantics: AbsenceSemantics = "none"

    @model_validator(mode="after")
    def _validate_binding(self) -> "CoverageSubclaimBinding":
        if self.kind == "evidence-kind":
            if self.target not in {
                "local-config",
                "normalized-config",
                "registry-export",
                "safe-probe",
                "policy-review",
            }:
                raise ValueError(
                    "evidence-kind bindings must target a known evidence kind."
                )
            if self.strength is not None or self.origin is not None:
                raise ValueError(
                    "evidence-kind bindings cannot declare registry mapping provenance."
                )
            if self.absence_semantics != "none":
                raise ValueError(
                    "evidence-kind bindings cannot declare automated pass semantics."
                )
            return self
        if self.strength is None or self.origin is None:
            raise ValueError(
                "rule and control bindings require both strength and origin."
            )
        return self


class CoverageSubclaim(_StrictModel):
    subclaim_id: Identifier
    title: NonEmptyText
    mandatory: bool = True
    implemented: bool = True
    bindings: tuple[CoverageSubclaimBinding, ...] = Field(default=(), max_length=64)
    limitations: tuple[NonEmptyText, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def _validate_subclaim(self) -> "CoverageSubclaim":
        if self.implemented and not self.bindings:
            raise ValueError("Implemented subclaims require at least one binding.")
        return self


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


class DenominatorChangeNote(_StrictModel):
    change_id: Identifier
    delta_applicable: int
    reason: NonEmptyText
    change_ref: NonEmptyText


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
    subclaims: tuple[CoverageSubclaim, ...] = Field(default=(), max_length=64)
    provenance: ItemProvenance


class CoverageSource(_StrictModel):
    source_id: Identifier
    title: NonEmptyText
    version: NonEmptyText
    authority_url: AnyHttpUrl
    scope_note: NonEmptyText
    expected_summary: CoverageSummary
    denominator_notes: tuple[DenominatorChangeNote, ...] = Field(
        default=(),
        max_length=16,
    )
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


class SourceRecount(_StrictModel):
    source_id: Identifier
    title: NonEmptyText
    version: NonEmptyText
    applicable: int = Field(ge=0)
    full: int = Field(ge=0)
    partial: int = Field(ge=0)
    policy_review: int = Field(ge=0)
    uncovered: int = Field(ge=0)
    excluded: int = Field(ge=0)
    full_percent: Decimal = Field(ge=0, le=100, decimal_places=1)


class SourceCoverageDelta(_StrictModel):
    applicable: int
    full: int
    partial: int
    policy_review: int
    uncovered: int
    excluded: int


class CoverageStatusChange(_StrictModel):
    source_id: Identifier
    item_id: Identifier
    title: NonEmptyText
    from_status: CoverageStatus
    to_status: CoverageStatus
    change_ref: NonEmptyText


class GeneratedCoverageArtifact(_StrictModel):
    label: Identifier
    path: str = Field(min_length=1, max_length=4096)
    content: str = Field(min_length=1)


class ReconciledSourceCoverage(_StrictModel):
    source_id: Identifier
    title: NonEmptyText
    baseline: SourceRecount
    current: SourceRecount
    delta: SourceCoverageDelta
    changed_items: tuple[CoverageStatusChange, ...] = Field(default=(), max_length=128)
    denominator_notes: tuple[DenominatorChangeNote, ...] = Field(
        default=(),
        max_length=16,
    )


class CoverageReconciliation(_StrictModel):
    schema_version: Literal[1] = 1
    sources: tuple[ReconciledSourceCoverage, ...] = Field(
        min_length=1,
        max_length=32,
    )
    artifacts: tuple[GeneratedCoverageArtifact, ...] = Field(
        min_length=1,
        max_length=16,
    )


__all__ = [
    "AcceptedProgramRevision",
    "AbsenceSemantics",
    "AssessableControlEvidence",
    "AssessableRuleEvidence",
    "Applicability",
    "ControlReference",
    "CoverageReconciliation",
    "CoverageEvidence",
    "CoverageItem",
    "CoverageLedger",
    "CoverageLedgerIssue",
    "CoverageSource",
    "CoverageStatusChange",
    "CoverageStatus",
    "CoverageSubclaim",
    "CoverageSubclaimBinding",
    "CoverageSummary",
    "DenominatorChangeNote",
    "EvidenceKind",
    "Exclusion",
    "GeneratedCoverageArtifact",
    "ItemProvenance",
    "LedgerSnapshot",
    "MappingOrigin",
    "MappingStrength",
    "ReconciledSourceCoverage",
    "RegistryReferenceClaim",
    "SourceCoverageDelta",
    "SourceCoverageSummary",
    "SourceRecount",
]
