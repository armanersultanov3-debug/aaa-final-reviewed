"""Versioned audit-policy models."""

from __future__ import annotations

import ipaddress
import re
from datetime import date, datetime
from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit

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
NginxSensitiveLocationKind = Literal[
    "admin",
    "documentation",
    "monitoring",
    "internal_api",
    "support",
    "custom",
]
NginxLocationSelectorModifier = Literal[
    "exact",
    "prefix",
    "prefix_no_regex",
    "regex",
    "regex_i",
    "named",
]
NginxSensitiveLocationExposure = Literal["external", "internal_only", "disabled"]
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


class NginxLocationSelector(_StrictModel):
    modifier: NginxLocationSelectorModifier
    pattern: NonEmptyText
    source_path: NonEmptyText | None = None

    @model_validator(mode="after")
    def validate_selector(self) -> "NginxLocationSelector":
        if self.modifier == "named":
            if not self.pattern.startswith("@"):
                raise ValueError("named location selectors must start with '@'.")
            return self
        if self.modifier in {"exact", "prefix", "prefix_no_regex"} and not self.pattern.startswith("/"):
            raise ValueError("non-regex location selectors must start with '/'.")
        if self.modifier in {"regex", "regex_i"}:
            _validate_supported_regex(
                self.pattern,
                flags=re.IGNORECASE if self.modifier == "regex_i" else 0,
            )
        return self


class _EmptySensitiveControl(_StrictModel):
    pass


class NginxIpAllowlistRequirement(_StrictModel):
    allowed_cidrs: tuple[NonEmptyText, ...] = Field(min_length=1, max_length=64)
    require_deny_all_fallback: bool = False

    @model_validator(mode="after")
    def validate_allowed_cidrs(self) -> "NginxIpAllowlistRequirement":
        for entry in self.allowed_cidrs:
            _parse_ip_or_cidr(entry)
        return self


class NginxSensitiveLocationRequirement(_StrictModel):
    all_of: tuple["NginxSensitiveLocationRequirement", ...] = Field(default=(), max_length=8)
    one_of: tuple["NginxSensitiveLocationRequirement", ...] = Field(default=(), max_length=8)
    satisfy: Literal["all", "any"] | None = None
    internal: _EmptySensitiveControl | None = None
    deny_all: _EmptySensitiveControl | None = None
    auth_basic: _EmptySensitiveControl | None = None
    auth_request: _EmptySensitiveControl | None = None
    auth_jwt: _EmptySensitiveControl | None = None
    auth_oidc: _EmptySensitiveControl | None = None
    ip_allowlist: NginxIpAllowlistRequirement | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> "NginxSensitiveLocationRequirement":
        composite_count = int(bool(self.all_of)) + int(bool(self.one_of))
        leaf_count = sum(
            requirement is not None
            for requirement in (
                self.internal,
                self.deny_all,
                self.auth_basic,
                self.auth_request,
                self.auth_jwt,
                self.auth_oidc,
                self.ip_allowlist,
            )
        )
        if composite_count + leaf_count != 1:
            raise ValueError(
                "sensitive location requirements must declare exactly one composite or leaf control."
            )
        if self.satisfy is not None and composite_count != 1:
            raise ValueError("satisfy is supported only on composite requirement nodes.")
        return self


class NginxSensitiveLocationEntry(_StrictModel):
    entry_id: Identifier
    kind: NginxSensitiveLocationKind
    server_names: tuple[NonEmptyText, ...] = Field(min_length=1, max_length=128)
    declared_location: NginxLocationSelector | None = None
    sample_uris: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)
    exposure: NginxSensitiveLocationExposure
    required_controls: NginxSensitiveLocationRequirement

    @model_validator(mode="after")
    def validate_entry(self) -> "NginxSensitiveLocationEntry":
        if self.declared_location is None and not self.sample_uris:
            raise ValueError(
                "sensitive location entries must declare a location selector, sample_uris, or both."
            )
        for uri in self.sample_uris:
            _validate_sensitive_location_sample_uri(uri)
        if self.exposure == "disabled" and not _requirement_tree_has_control(
            self.required_controls,
            control_name="deny_all",
        ):
            raise ValueError(
                "exposure 'disabled' requires a deny_all requirement or equivalent unconditional deny control."
            )
        if self.exposure == "internal_only" and not (
            _requirement_tree_has_control(self.required_controls, control_name="internal")
            or _requirement_tree_has_control(self.required_controls, control_name="deny_all")
        ):
            raise ValueError(
                "exposure 'internal_only' requires an internal or deny_all requirement."
            )
        return self


class NginxSensitiveLocationsPolicy(_StrictModel):
    catalog: tuple[NginxSensitiveLocationEntry, ...] = Field(min_length=1, max_length=128)
    unmatched_entries: UnmatchedRouteDisposition = "indeterminate"
    allow_unresolved_internal_redirects: bool = False


class NginxPolicy(_StrictModel):
    reverse_proxy_headers: NginxReverseProxyHeadersPolicy | None = None
    logging: NginxLoggingPolicy | None = None
    sensitive_locations: NginxSensitiveLocationsPolicy | None = None


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
    "NginxIpAllowlistRequirement",
    "NginxLocationSelector",
    "NginxLocationSelectorModifier",
    "NginxLoggingConditionalPolicy",
    "NginxLoggingPolicy",
    "NginxLoggingProfile",
    "NginxLoggingSelector",
    "NginxLogVariable",
    "NginxPolicy",
    "NginxReverseProxyHeadersPolicy",
    "NginxSensitiveLocationEntry",
    "NginxSensitiveLocationExposure",
    "NginxSensitiveLocationKind",
    "NginxSensitiveLocationRequirement",
    "NginxSensitiveLocationsPolicy",
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


def _validate_supported_regex(pattern: str, *, flags: int = 0) -> None:
    if "(?<" in pattern or "\\K" in pattern or "(?>" in pattern or "(?R" in pattern or "(?0" in pattern:
        raise ValueError(f"Unsupported regex construct in location selector pattern {pattern!r}.")
    try:
        re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(f"Invalid regex location selector pattern {pattern!r}: {exc}.") from exc


def _parse_ip_or_cidr(value: str) -> None:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=True)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"Invalid IP or CIDR value {value!r}.") from exc


def _validate_sensitive_location_sample_uri(value: str) -> None:
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or parts.query or parts.fragment:
        raise ValueError(
            f"Sensitive location sample URI {value!r} must be an absolute path without scheme, host, query, or fragment."
        )
    if not value.startswith("/"):
        raise ValueError(f"Sensitive location sample URI {value!r} must start with '/'.")
    if value != _normalize_sensitive_location_uri(value):
        raise ValueError(
            f"Sensitive location sample URI {value!r} must already be normalized for static matching."
        )


def _normalize_sensitive_location_uri(value: str) -> str:
    decoded = unquote(value)
    normalized_parts: list[str] = []
    for part in decoded.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if normalized_parts:
                normalized_parts.pop()
            continue
        normalized_parts.append(part)
    normalized = "/" + "/".join(normalized_parts)
    if value.endswith("/") and normalized != "/":
        normalized += "/"
    compressed = re.sub(r"/{2,}", "/", normalized)
    return compressed or "/"


def _requirement_tree_has_control(
    requirement: NginxSensitiveLocationRequirement,
    *,
    control_name: str,
) -> bool:
    if getattr(requirement, control_name) is not None:
        return True
    return any(
        _requirement_tree_has_control(child, control_name=control_name)
        for child in (*requirement.all_of, *requirement.one_of)
    )


NginxSensitiveLocationRequirement.model_rebuild()
