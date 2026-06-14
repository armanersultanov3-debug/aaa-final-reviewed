"""Core result and reporting data models shared by local and external
analysis pipelines.

Defines :class:`Finding`, :class:`AnalysisIssue`, :class:`SourceLocation`,
and :class:`AnalysisResult` plus the literal type aliases used across
the analyzer surface (severity, mode, issue level, location kind).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from webconf_audit.execution_manifest import RuleExecutionManifest
    from webconf_audit.policy_models import ResolvedAuditPolicy

AnalysisMode = Literal["local", "external"]
Severity = Literal["info", "low", "medium", "high", "critical"]
IssueLevel = Literal["info", "warning", "error"]
ResultKind = Literal["finding", "analysis_issue"]
LocationKind = Literal["file", "xml", "endpoint", "url", "header", "tls", "check"]


class SourceLocation(BaseModel):
    mode: AnalysisMode
    kind: LocationKind
    file_path: str | None = None
    line: int | None = None
    xml_path: str | None = None
    target: str | None = None
    details: str | None = None


class _BaseResultEntry(BaseModel):
    location: SourceLocation | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(_BaseResultEntry):
    kind: Literal["finding"] = "finding"
    rule_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    effective_cause_key: tuple[str, ...] | None = None

    @model_validator(mode="after")
    def use_registered_severity(self) -> "Finding":
        try:
            from webconf_audit.rule_registry import registry
        except ImportError:
            return self

        meta = registry.get_meta(self.rule_id)
        if meta is not None and self.severity == meta.declared_severity:
            self.severity = meta.severity
        return self


class AnalysisIssue(_BaseResultEntry):
    kind: Literal["analysis_issue"] = "analysis_issue"
    code: str
    level: IssueLevel = "warning"
    message: str
    details: str | None = None


ControlAssessmentStatus = Literal["pass", "fail", "not-applicable", "indeterminate"]
ControlAssessmentEvidenceKind = Literal[
    "request-header",
    "response-header",
    "unsupported",
    "route",
]


class _StrictAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ControlAssessmentScope(_StrictAnalysisModel):
    server_scope_id: str
    route_scope_id: str
    route_selector: str | None = None
    server_name: str | None = None


class ControlAssessmentEvidence(_StrictAnalysisModel):
    kind: ControlAssessmentEvidenceKind
    status: str
    message: str
    header_name: str | None = None
    locations: tuple[SourceLocation, ...] = Field(default=(), max_length=64)
    declared_scope_id: str | None = None
    effective_scope_id: str | None = None
    values: tuple[str, ...] = Field(default=(), max_length=64)


class PolicyControlAssessment(_StrictAnalysisModel):
    schema_version: Literal[1] = 1
    control_id: str
    title: str
    status: ControlAssessmentStatus
    scope: ControlAssessmentScope
    summary: str
    evidence: tuple[ControlAssessmentEvidence, ...] = Field(default=(), max_length=512)
    related_rule_ids: tuple[str, ...] = Field(default=(), max_length=128)
    policy_source: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalysisResult(BaseModel):
    mode: AnalysisMode
    target: str
    server_type: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    issues: list[AnalysisIssue] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    control_assessments: list[PolicyControlAssessment] = Field(
        default_factory=list,
        exclude=True,
    )
    audit_policy: "ResolvedAuditPolicy | None" = Field(default=None, exclude=True)
    rule_execution: "RuleExecutionManifest | None" = Field(default=None, exclude=True)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def has_issues(self) -> bool:
        return bool(self.issues)


__all__ = [
    "AnalysisIssue",
    "AnalysisMode",
    "AnalysisResult",
    "ControlAssessmentEvidence",
    "ControlAssessmentScope",
    "ControlAssessmentStatus",
    "Finding",
    "IssueLevel",
    "LocationKind",
    "PolicyControlAssessment",
    "ResultKind",
    "Severity",
    "SourceLocation",
]


def rebuild_analysis_result_models() -> None:
    from webconf_audit.execution_manifest import RuleExecutionManifest
    from webconf_audit.policy_models import ResolvedAuditPolicy

    AnalysisResult.model_rebuild(
        _types_namespace={
            "ResolvedAuditPolicy": ResolvedAuditPolicy,
            "RuleExecutionManifest": RuleExecutionManifest,
        }
    )


try:
    rebuild_analysis_result_models()
except ImportError:
    pass
