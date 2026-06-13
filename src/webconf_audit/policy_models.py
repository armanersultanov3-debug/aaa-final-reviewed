"""Versioned audit-policy models."""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from webconf_audit.coverage_models import Identifier, NonEmptyText, RuleIdentifier

PolicySchemaVersion = Literal[1]
ControlDisposition = Literal[
    "required",
    "advisory",
    "review",
    "not-applicable",
]
EvidenceExpectation = Literal[
    "ledger-default",
    "declared-direct",
    "declared-partial",
    "operator-review",
]
AnalysisMode = Literal["local", "external"]
ServerType = Literal["nginx", "apache", "lighttpd", "iis", "generic"]
InheritedFrom = Literal["policy-default", "source", "control"]
TargetGlob = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=512),
]
SHA256Hex = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    ),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PolicyDefaults(_StrictModel):
    disposition: Literal["required", "advisory"] = "advisory"
    evidence_expectation: Literal["ledger-default"] = "ledger-default"
    include_unmapped_findings: bool = True
    require_complete_execution_manifest: bool = True


class TargetSelector(_StrictModel):
    mode: AnalysisMode
    server_type: ServerType | None = None
    target_glob: TargetGlob | None = None


class ControlPolicy(_StrictModel):
    item_id: Identifier
    disposition: ControlDisposition
    evidence_expectation: EvidenceExpectation = "ledger-default"
    required_rule_ids: tuple[RuleIdentifier, ...] = Field(default=(), max_length=128)
    rationale: NonEmptyText
    ticket_ref: NonEmptyText | None = None
    review_due: date | None = None


class SourcePolicy(_StrictModel):
    source_id: Identifier
    disposition: Literal["required", "advisory"] | None = None
    controls: tuple[ControlPolicy, ...] = Field(default=(), max_length=512)


class AuditProfile(_StrictModel):
    profile_id: Identifier
    title: NonEmptyText
    selectors: tuple[TargetSelector, ...] = Field(min_length=1, max_length=32)
    sources: tuple[SourcePolicy, ...] = Field(min_length=1, max_length=32)
    requested_opt_in_tags: tuple[Identifier, ...] = Field(default=(), max_length=32)


class PolicyProvenance(_StrictModel):
    owner: NonEmptyText
    approved_on: date
    change_ref: NonEmptyText


class LoadedPolicyProvenance(_StrictModel):
    path: NonEmptyText
    sha256: SHA256Hex
    loaded_at: datetime


class AuditPolicy(_StrictModel):
    schema_version: PolicySchemaVersion
    policy_id: Identifier
    policy_version: NonEmptyText
    title: NonEmptyText
    description: NonEmptyText
    defaults: PolicyDefaults
    profiles: tuple[AuditProfile, ...] = Field(min_length=1, max_length=64)
    provenance: PolicyProvenance
    loaded_provenance: LoadedPolicyProvenance | None = Field(
        default=None,
        exclude=True,
    )


class AuditTarget(_StrictModel):
    mode: AnalysisMode
    server_type: ServerType | None = None
    target: NonEmptyText


class ResolvedTarget(_StrictModel):
    mode: AnalysisMode
    server_type: ServerType | None = None
    target: NonEmptyText


class ResolvedControlPolicy(_StrictModel):
    item_id: Identifier
    disposition: ControlDisposition
    evidence_expectation: EvidenceExpectation
    required_rule_ids: tuple[RuleIdentifier, ...] = Field(default=(), max_length=128)
    rationale: NonEmptyText
    ticket_ref: NonEmptyText | None = None
    review_due: date | None = None
    inherited_from: InheritedFrom


class ResolvedSourcePolicy(_StrictModel):
    source_id: Identifier
    controls: tuple[ResolvedControlPolicy, ...] = Field(min_length=1, max_length=512)


class ResolvedAuditPolicy(_StrictModel):
    schema_version: PolicySchemaVersion = 1
    policy_id: Identifier
    policy_version: NonEmptyText
    profile_id: Identifier
    raw_sha256: SHA256Hex
    resolved_sha256: SHA256Hex
    target: ResolvedTarget
    requested_opt_in_tags: tuple[Identifier, ...] = Field(default=(), max_length=32)
    sources: tuple[ResolvedSourcePolicy, ...] = Field(min_length=1, max_length=32)


class AuditPolicyIssue(_StrictModel):
    code: NonEmptyText
    message: NonEmptyText
    profile_id: str | None = None
    source_id: str | None = None
    item_id: str | None = None
    rule_id: str | None = None
    path: str | None = None


__all__ = [
    "AnalysisMode",
    "AuditPolicy",
    "AuditPolicyIssue",
    "AuditProfile",
    "AuditTarget",
    "ControlDisposition",
    "ControlPolicy",
    "EvidenceExpectation",
    "LoadedPolicyProvenance",
    "PolicyDefaults",
    "PolicyProvenance",
    "PolicySchemaVersion",
    "ResolvedAuditPolicy",
    "ResolvedControlPolicy",
    "ResolvedSourcePolicy",
    "ResolvedTarget",
    "ServerType",
    "SourcePolicy",
    "TargetSelector",
]
