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
NginxConditionMode = Literal["forbid", "allow_dynamic", "allow_listed"]
NginxEscapeMode = Literal["default", "json", "none"]
NginxErrorLogSeverity = Literal[
    "debug",
    "info",
    "notice",
    "warn",
    "error",
    "crit",
    "alert",
    "emerg",
]
NginxAccessDestinationKind = Literal["file", "syslog", "stderr"]
NginxErrorDestinationKind = Literal["file", "syslog", "stderr", "memory", "null_device"]
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
NginxLogVariable = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=2,
        max_length=256,
        pattern=r"^\$(?:\{[A-Za-z0-9_]+\}|[A-Za-z0-9_]+)$",
    ),
]
NginxFieldGroupName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$",
    ),
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


class NginxLoggingSelector(_StrictModel):
    server_names: tuple[NonEmptyText, ...] = Field(default=(), max_length=128)
    location_patterns: tuple[NonEmptyText, ...] = Field(default=(), max_length=128)


class NginxLoggingConditionalPolicy(_StrictModel):
    mode: NginxConditionMode
    allowed_conditions: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_mode_requirements(self) -> "NginxLoggingConditionalPolicy":
        if self.mode == "allow_listed" and not self.allowed_conditions:
            raise ValueError("allow_listed conditional mode requires allowed_conditions.")
        if self.mode != "allow_listed" and self.allowed_conditions:
            raise ValueError(
                "allowed_conditions is supported only for conditional mode allow_listed."
            )
        return self


class NginxAccessDestinationEntry(_StrictModel):
    kind: NginxAccessDestinationKind
    path: NonEmptyText | None = None
    prefix: NonEmptyText | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> "NginxAccessDestinationEntry":
        if self.kind == "file":
            if self.path is None:
                raise ValueError("file access-log destinations require path.")
            if self.prefix is not None:
                raise ValueError("file access-log destinations cannot declare prefix.")
        elif self.kind == "syslog":
            if self.prefix is None:
                raise ValueError("syslog access-log destinations require prefix.")
            if self.path is not None:
                raise ValueError("syslog access-log destinations cannot declare path.")
        else:
            if self.path is not None or self.prefix is not None:
                raise ValueError(
                    "stderr access-log destinations cannot declare path or prefix."
                )
        return self


class NginxAccessDestinationPolicy(_StrictModel):
    allowed: tuple[NginxAccessDestinationEntry, ...] = Field(default=(), max_length=64)
    require_at_least_one_remote: bool = False
    allow_variable_paths: bool = False

    @model_validator(mode="after")
    def validate_remote_requirements(self) -> "NginxAccessDestinationPolicy":
        if self.require_at_least_one_remote and not any(
            entry.kind == "syslog" for entry in self.allowed
        ):
            raise ValueError(
                "require_at_least_one_remote requires at least one syslog allowed destination."
            )
        return self


class NginxAccessFormatPolicy(_StrictModel):
    allowed_names: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)
    require_escape: NginxEscapeMode | None = None
    required_field_groups: dict[NginxFieldGroupName, tuple[NginxLogVariable, ...]] = Field(
        default_factory=dict
    )
    forbidden_variables: tuple[NginxLogVariable, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_groups(self) -> "NginxAccessFormatPolicy":
        normalized_required: set[str] = set()
        for group_name, variables in self.required_field_groups.items():
            if not variables:
                raise ValueError(
                    f"required field group {group_name!r} must contain at least one variable."
                )
            normalized_required.update(_normalize_nginx_variable(variable) for variable in variables)
        forbidden = {
            _normalize_nginx_variable(variable)
            for variable in self.forbidden_variables
        }
        overlap = sorted(normalized_required & forbidden)
        if overlap:
            raise ValueError(
                "forbidden_variables cannot also satisfy required field groups: "
                + ", ".join(overlap)
            )
        return self


class NginxAccessLoggingPolicy(_StrictModel):
    required: bool = True
    allow_off: bool = False
    conditional: NginxLoggingConditionalPolicy
    destinations: NginxAccessDestinationPolicy
    formats: NginxAccessFormatPolicy


class NginxErrorDestinationPolicy(_StrictModel):
    allowed_kinds: tuple[NginxErrorDestinationKind, ...] = Field(
        min_length=1,
        max_length=8,
    )
    forbidden_paths: tuple[NonEmptyText, ...] = Field(default=(), max_length=32)


class NginxErrorThresholdPolicy(_StrictModel):
    most_restrictive_allowed: NginxErrorLogSeverity
    allow_debug: bool = False


class NginxErrorLoggingPolicy(_StrictModel):
    required: bool = True
    require_explicit_destination: bool = False
    destinations: NginxErrorDestinationPolicy
    threshold: NginxErrorThresholdPolicy


class NginxLoggingProfile(_StrictModel):
    profile_id: Identifier
    applies_to: NginxLoggingSelector
    access: NginxAccessLoggingPolicy | None = None
    error: NginxErrorLoggingPolicy | None = None

    @model_validator(mode="after")
    def validate_non_empty(self) -> "NginxLoggingProfile":
        if self.access is None and self.error is None:
            raise ValueError("logging profile must declare access or error requirements.")
        return self


class NginxLoggingPolicy(_StrictModel):
    profiles: tuple[NginxLoggingProfile, ...] = Field(min_length=1, max_length=128)
    unmatched_scopes: UnmatchedRouteDisposition = "indeterminate"


class NginxPolicy(_StrictModel):
    reverse_proxy_headers: NginxReverseProxyHeadersPolicy | None = None
    logging: NginxLoggingPolicy | None = None


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
    "NginxAccessDestinationEntry",
    "NginxAccessDestinationKind",
    "NginxAccessDestinationPolicy",
    "NginxAccessFormatPolicy",
    "NginxAccessLoggingPolicy",
    "NginxConditionMode",
    "NginxErrorDestinationKind",
    "NginxErrorDestinationPolicy",
    "NginxErrorLogSeverity",
    "NginxErrorLoggingPolicy",
    "NginxErrorThresholdPolicy",
    "NginxEscapeMode",
    "NginxFieldGroupName",
    "NginxLoggingConditionalPolicy",
    "NginxLoggingPolicy",
    "NginxLoggingProfile",
    "NginxLoggingSelector",
    "NginxLogVariable",
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


def _normalize_nginx_variable(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith("${") and stripped.endswith("}"):
        return f"${stripped[2:-1]}"
    return stripped
