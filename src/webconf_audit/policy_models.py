"""Versioned audit-policy models."""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

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
UpstreamFamily = Literal["proxy", "fastcgi", "grpc", "uwsgi"]
UnmatchedRouteDisposition = Literal["not-applicable", "fail", "indeterminate"]
TargetGlob = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=512),
]
HeaderName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=256,
        pattern=r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$",
    ),
]
HeaderExpression = Annotated[
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


class ReverseProxyHeaderRequirement(_StrictModel):
    any_of: tuple[HeaderExpression, ...] = Field(min_length=1, max_length=32)


class ReverseProxyHostPolicy(_StrictModel):
    allowed_values: tuple[HeaderExpression, ...] = Field(default=(), max_length=32)
    allow_fixed_literals: bool = False

    @model_validator(mode="after")
    def validate_non_empty(self) -> "ReverseProxyHostPolicy":
        if not self.allowed_values and not self.allow_fixed_literals:
            raise ValueError(
                "host policy must declare allowed_values or allow_fixed_literals."
            )
        return self


class ReverseProxyRequestHeadersPolicy(_StrictModel):
    required: dict[HeaderName, ReverseProxyHeaderRequirement] = Field(default_factory=dict)
    host: ReverseProxyHostPolicy | None = None
    forbidden_client_variables: tuple[HeaderExpression, ...] = Field(
        default=(),
        max_length=64,
    )


class ReverseProxyResponseHeadersPolicy(_StrictModel):
    must_hide: tuple[HeaderName, ...] = Field(default=(), max_length=64)
    must_not_pass: tuple[HeaderName, ...] = Field(default=(), max_length=64)
    allow_explicit_pass: tuple[HeaderName, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_contradictions(self) -> "ReverseProxyResponseHeadersPolicy":
        must_hide = {header.lower() for header in self.must_hide}
        allowed_pass = {header.lower() for header in self.allow_explicit_pass}
        if must_hide & allowed_pass:
            raise ValueError(
                "response header policy cannot require must_hide and allow_explicit_pass for the same header."
            )
        return self


class ReverseProxyRouteSelector(_StrictModel):
    upstream_families: tuple[UpstreamFamily, ...] = Field(default=(), max_length=4)
    server_names: tuple[NonEmptyText, ...] = Field(default=(), max_length=128)
    location_patterns: tuple[NonEmptyText, ...] = Field(default=(), max_length=128)


class ReverseProxyHeaderProfile(_StrictModel):
    profile_id: Identifier
    applies_to: ReverseProxyRouteSelector
    request_headers: ReverseProxyRequestHeadersPolicy
    response_headers: ReverseProxyResponseHeadersPolicy


class NginxReverseProxyHeadersPolicy(_StrictModel):
    profiles: tuple[ReverseProxyHeaderProfile, ...] = Field(min_length=1, max_length=128)
    unmatched_routes: UnmatchedRouteDisposition = "indeterminate"


class NginxPolicy(_StrictModel):
    reverse_proxy_headers: NginxReverseProxyHeadersPolicy | None = None


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
    nginx: NginxPolicy | None = None
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
    nginx: NginxPolicy | None = None


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
    "HeaderExpression",
    "HeaderName",
    "LoadedPolicyProvenance",
    "NginxPolicy",
    "NginxReverseProxyHeadersPolicy",
    "PolicyDefaults",
    "PolicyProvenance",
    "PolicySchemaVersion",
    "ResolvedAuditPolicy",
    "ResolvedControlPolicy",
    "ResolvedSourcePolicy",
    "ResolvedTarget",
    "ReverseProxyHeaderProfile",
    "ReverseProxyHeaderRequirement",
    "ReverseProxyHostPolicy",
    "ReverseProxyRequestHeadersPolicy",
    "ReverseProxyResponseHeadersPolicy",
    "ReverseProxyRouteSelector",
    "ServerType",
    "SourcePolicy",
    "TargetSelector",
    "UnmatchedRouteDisposition",
    "UpstreamFamily",
]
