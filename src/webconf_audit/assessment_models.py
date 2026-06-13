"""Versioned models for control assessment input and output artifacts."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from webconf_audit.coverage_models import (
    AbsenceSemantics,
    ControlReference,
    CoverageStatus,
    Identifier,
    MappingOrigin,
    MappingStrength,
    NonEmptyText,
    RuleIdentifier,
)
from webconf_audit.execution_manifest import RuleExecutionManifest
from webconf_audit.models import AnalysisIssue, AnalysisMode, Severity, SourceLocation
from webconf_audit.policy_models import ControlDisposition, EvidenceExpectation, ResolvedAuditPolicy

SHA256Hex = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    ),
]
AssessmentStatus = Literal[
    "pass",
    "fail",
    "partial",
    "review",
    "indeterminate",
    "not-assessed",
    "not-applicable",
]
AssessmentIssueSeverity = Literal["error", "warning"]
ExecutionState = Literal["completed", "skipped", "failed"]
MissingEvidenceReason = Literal[
    "not-selected",
    "skipped",
    "execution-failed",
    "mode-unavailable",
    "server-unavailable",
    "ledger-uncovered",
    "no-pass-semantics",
    "operator-evidence-required",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GeneratorIdentity(_StrictModel):
    package_name: NonEmptyText
    package_version: NonEmptyText
    registry_revision: NonEmptyText


class FindingDerivedReference(_StrictModel):
    standard: NonEmptyText
    reference: NonEmptyText


class FindingStandardReference(_StrictModel):
    standard: NonEmptyText
    reference: NonEmptyText
    coverage: MappingStrength
    origin: MappingOrigin
    tier: Literal["primary", "secondary"] | None = None
    url: NonEmptyText | None = None
    note: NonEmptyText | None = None
    derived_from: FindingDerivedReference | None = None


class AnalysisReportFinding(_StrictModel):
    kind: Literal["finding"] = "finding"
    rule_id: RuleIdentifier
    title: NonEmptyText
    severity: Severity
    description: NonEmptyText
    recommendation: NonEmptyText
    location: SourceLocation | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    effective_cause_key: tuple[NonEmptyText, ...] | None = Field(
        default=None,
        max_length=64,
    )
    fingerprint: SHA256Hex
    location_display: NonEmptyText | None = None
    standards: tuple[FindingStandardReference, ...] = Field(default=(), max_length=256)
    standards_secondary: tuple[FindingStandardReference, ...] = Field(
        default=(),
        max_length=256,
    )


class SuppressedFindingRecord(_StrictModel):
    fingerprint: SHA256Hex
    rule_id: RuleIdentifier
    reason: NonEmptyText
    expires: date
    matched_by: NonEmptyText
    suppression_index: int = Field(ge=1)
    source_path: NonEmptyText | None = None
    finding: AnalysisReportFinding


class AnalysisReportResult(_StrictModel):
    mode: AnalysisMode
    target: NonEmptyText
    server_type: NonEmptyText | None = None
    findings: tuple[AnalysisReportFinding, ...] = Field(default=(), max_length=20000)
    issues: tuple[AnalysisIssue, ...] = Field(default=(), max_length=20000)
    diagnostics: tuple[NonEmptyText, ...] = Field(default=(), max_length=20000)
    audit_policy: ResolvedAuditPolicy | None = Field(default=None, exclude=True)
    rule_execution: RuleExecutionManifest | None = Field(default=None, exclude=True)
    suppressed_findings: tuple[SuppressedFindingRecord, ...] = Field(
        default=(),
        max_length=20000,
    )
    metadata_issues: tuple["AssessmentIssue", ...] = Field(default=(), exclude=True)


class AnalysisReport(_StrictModel):
    schema_version: int | None = None
    generator: GeneratorIdentity | None = None
    generated_at: datetime | None = None
    results: tuple[AnalysisReportResult, ...] = Field(default=(), max_length=512)
    findings: tuple[AnalysisReportFinding, ...] = Field(default=(), max_length=20000)
    issues: tuple[AnalysisIssue, ...] = Field(default=(), max_length=20000)
    source_path: NonEmptyText | None = Field(default=None, exclude=True)
    source_sha256: SHA256Hex | None = Field(default=None, exclude=True)
    load_issues: tuple["AssessmentIssue", ...] = Field(default=(), exclude=True)


class AssessmentIssue(_StrictModel):
    code: NonEmptyText
    severity: AssessmentIssueSeverity
    message: NonEmptyText
    source_id: Identifier | None = None
    item_id: Identifier | None = None
    rule_id: RuleIdentifier | None = None
    target_id: NonEmptyText | None = None


class AssessmentInputs(_StrictModel):
    analysis_report_sha256: SHA256Hex
    analysis_report_schema_version: int = Field(ge=1)
    ledger_snapshot_id: Identifier
    ledger_sha256: SHA256Hex
    policy_id: Identifier
    policy_version: NonEmptyText
    policy_raw_sha256: SHA256Hex
    policy_resolved_sha256: SHA256Hex
    execution_manifest_schema_version: int = Field(ge=1)


class AssessmentTarget(_StrictModel):
    target_id: NonEmptyText
    display_name: NonEmptyText
    mode: AnalysisMode
    server_type: NonEmptyText | None = None


class CoverageSummaryReference(_StrictModel):
    applicable: int = Field(ge=0)
    full: int = Field(ge=0)
    partial: int = Field(ge=0)
    policy_review: int = Field(ge=0)
    uncovered: int = Field(ge=0)
    full_percent: Decimal = Field(ge=0, le=100, decimal_places=1)


class AssessmentEvidence(_StrictModel):
    rule_id: RuleIdentifier
    target_id: NonEmptyText
    mapping_strength: MappingStrength
    mapping_origin: MappingOrigin
    absence_semantics: AbsenceSemantics
    execution_state: ExecutionState
    finding_ids: tuple[SHA256Hex, ...] = Field(default=(), max_length=256)
    finding_severities: tuple[Severity, ...] = Field(default=(), max_length=256)
    suppressed: bool = False
    suppression_refs: tuple[NonEmptyText, ...] = Field(default=(), max_length=256)
    observed_facets: tuple[NonEmptyText, ...] = Field(default=(), max_length=256)
    note: NonEmptyText


class MissingEvidence(_StrictModel):
    rule_id: RuleIdentifier | None = None
    expectation: EvidenceExpectation
    reason: MissingEvidenceReason
    detail: NonEmptyText


class ControlAssessment(_StrictModel):
    source_id: Identifier
    item_id: Identifier
    title: NonEmptyText
    references: tuple[ControlReference, ...] = Field(min_length=1, max_length=64)
    ledger_status: CoverageStatus
    policy_disposition: ControlDisposition
    status: AssessmentStatus
    rationale: NonEmptyText
    evidence: tuple[AssessmentEvidence, ...] = Field(default=(), max_length=4096)
    missing_evidence: tuple[MissingEvidence, ...] = Field(default=(), max_length=4096)
    issues: tuple[NonEmptyText, ...] = Field(default=(), max_length=256)


class AssessmentSummary(_StrictModel):
    total: int = Field(ge=0)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    partial: int = Field(ge=0)
    review: int = Field(ge=0)
    indeterminate: int = Field(ge=0)
    not_assessed: int = Field(ge=0)
    not_applicable: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_total(self) -> "AssessmentSummary":
        counted = (
            self.passed
            + self.failed
            + self.partial
            + self.review
            + self.indeterminate
            + self.not_assessed
            + self.not_applicable
        )
        if counted != self.total:
            raise ValueError("AssessmentSummary totals do not add up.")
        return self


class SourceAssessment(_StrictModel):
    source_id: Identifier
    title: NonEmptyText
    version: NonEmptyText
    coverage_summary: CoverageSummaryReference
    controls: tuple[ControlAssessment, ...] = Field(default=(), max_length=4096)
    summary: AssessmentSummary


class ControlAssessmentReport(_StrictModel):
    schema_version: Literal[1] = 1
    report_id: NonEmptyText
    generated_at: datetime
    generator: GeneratorIdentity
    inputs: AssessmentInputs
    targets: tuple[AssessmentTarget, ...] = Field(default=(), max_length=512)
    sources: tuple[SourceAssessment, ...] = Field(default=(), max_length=128)
    summary: AssessmentSummary
    issues: tuple[AssessmentIssue, ...] = Field(default=(), max_length=4096)


AnalysisReportResult.model_rebuild(_types_namespace={"AssessmentIssue": AssessmentIssue})
AnalysisReport.model_rebuild(_types_namespace={"AssessmentIssue": AssessmentIssue})


__all__ = [
    "AnalysisReport",
    "AnalysisReportFinding",
    "AnalysisReportResult",
    "AssessmentEvidence",
    "AssessmentInputs",
    "AssessmentIssue",
    "AssessmentStatus",
    "AssessmentSummary",
    "AssessmentTarget",
    "ControlAssessment",
    "ControlAssessmentReport",
    "CoverageSummaryReference",
    "ExecutionState",
    "FindingStandardReference",
    "GeneratorIdentity",
    "MissingEvidence",
    "MissingEvidenceReason",
    "SHA256Hex",
    "SourceAssessment",
    "SuppressedFindingRecord",
]
