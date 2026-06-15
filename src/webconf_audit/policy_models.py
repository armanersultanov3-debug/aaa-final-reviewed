"""Versioned audit-policy models."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from datetime import date, datetime
from fractions import Fraction
from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

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
NginxAdditionalZonesMode = Literal["allow", "require_in_inventory", "forbid"]
NginxRateLimitDelayMode = Literal["default", "delayed", "nodelay"]
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
NginxResponseKind = Literal[
    "html_document",
    "api",
    "static_asset",
    "download",
    "redirect",
    "error",
    "internal",
    "custom",
]
NginxResponseScheme = Literal["http", "https"]
NginxConditionalBranchDisposition = Literal["require_all"]
CspBaselinePolicy = Literal["any_enforcing", "each_enforcing"]
CspAdditionalPoliciesMode = Literal["allow", "require_parseable", "forbid"]
CspScriptAuthorizationMode = Literal[
    "allowlist",
    "nonce",
    "hash",
    "nonce_or_hash",
    "strict_nonce_or_hash",
]
CspFrameAncestorsMode = Literal["deny"]
CspReportingMode = Literal["report-to", "report-uri"]
SingleValueHeaderMode = Literal["transitional_optional"]
TLSTrustMode = Literal["system", "custom"]
TLSRequiredEvidence = Literal[
    "handshake",
    "certificate_name",
    "certificate_chain",
    "protocol_support",
    "negotiated_cipher",
    "ocsp_stapling",
]
TLSObservationRequirement = TLSRequiredEvidence
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
NginxZoneIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=160,
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

_DIRECTIVE_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
_CSP_HASH_SOURCE_PATTERN = (
    r"^(?:"
    r"'(?P<quoted_algorithm>sha256|sha384|sha512)-(?P<quoted_value>[A-Za-z0-9+/_-]+={0,2})'"
    r"|"
    r"(?P<plain_algorithm>sha256|sha384|sha512)-(?P<plain_value>[A-Za-z0-9+/_-]+={0,2})"
    r")$"
)
_CSP_HASH_RE = re.compile(_CSP_HASH_SOURCE_PATTERN, re.IGNORECASE)


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


class NginxByteSize(_StrictModel):
    raw: NonEmptyText
    bytes: int

    @model_validator(mode="before")
    @classmethod
    def parse_from_string(cls, value):
        if isinstance(value, str):
            return {"raw": value, "bytes": _parse_nginx_size(value)}
        return value

    @model_validator(mode="after")
    def validate_positive(self) -> "NginxByteSize":
        if self.bytes <= 0:
            raise ValueError("Nginx byte sizes must be positive.")
        return self


class NginxRequestRate(_StrictModel):
    raw: NonEmptyText
    requests: int
    period_seconds: int

    @model_validator(mode="before")
    @classmethod
    def parse_from_string(cls, value):
        if isinstance(value, str):
            parsed_requests, parsed_period_seconds = _parse_request_rate(value)
            return {
                "raw": value,
                "requests": parsed_requests,
                "period_seconds": parsed_period_seconds,
            }
        return value

    @model_validator(mode="after")
    def validate_positive(self) -> "NginxRequestRate":
        if self.requests <= 0 or self.period_seconds <= 0:
            raise ValueError("Nginx request rates must be positive.")
        return self


class NginxRequestRateRange(_StrictModel):
    min: NginxRequestRate | None = None
    max: NginxRequestRate | None = None

    @model_validator(mode="after")
    def validate_bounds(self) -> "NginxRequestRateRange":
        if self.min is None and self.max is None:
            raise ValueError("Request-rate ranges must declare min or max.")
        if (
            self.min is not None
            and self.max is not None
            and _request_rate_ratio(self.min) > _request_rate_ratio(self.max)
        ):
            raise ValueError("Request-rate range min must not exceed max.")
        return self


class NginxIntegerRange(_StrictModel):
    min: int | None = Field(default=None, ge=0)
    max: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_bounds(self) -> "NginxIntegerRange":
        if self.min is None and self.max is None:
            raise ValueError("Integer ranges must declare min or max.")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError("Integer range min must not exceed max.")
        return self


class NginxPositiveIntegerRange(_StrictModel):
    min: int | None = Field(default=None, ge=1)
    max: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_bounds(self) -> "NginxPositiveIntegerRange":
        if self.min is None and self.max is None:
            raise ValueError("Positive integer ranges must declare min or max.")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError("Positive integer range min must not exceed max.")
        return self


class NginxRequestZoneInventoryEntry(_StrictModel):
    allowed_keys: tuple[NonEmptyText, ...] = Field(min_length=1, max_length=32)
    min_size: NginxByteSize | None = None
    max_size: NginxByteSize | None = None
    rate: NginxRequestRateRange

    @model_validator(mode="after")
    def validate_sizes(self) -> "NginxRequestZoneInventoryEntry":
        if (
            self.min_size is not None
            and self.max_size is not None
            and self.min_size.bytes > self.max_size.bytes
        ):
            raise ValueError("Zone inventory min_size must not exceed max_size.")
        return self


class NginxConnectionZoneInventoryEntry(_StrictModel):
    allowed_keys: tuple[NonEmptyText, ...] = Field(min_length=1, max_length=32)
    min_size: NginxByteSize | None = None
    max_size: NginxByteSize | None = None

    @model_validator(mode="after")
    def validate_sizes(self) -> "NginxConnectionZoneInventoryEntry":
        if (
            self.min_size is not None
            and self.max_size is not None
            and self.min_size.bytes > self.max_size.bytes
        ):
            raise ValueError("Zone inventory min_size must not exceed max_size.")
        return self


class NginxRateLimitZoneInventory(_StrictModel):
    request: dict[NginxZoneIdentifier, NginxRequestZoneInventoryEntry] = Field(default_factory=dict)
    connection: dict[NginxZoneIdentifier, NginxConnectionZoneInventoryEntry] = Field(default_factory=dict)


class NginxRateLimitSelector(_StrictModel):
    server_names: tuple[NonEmptyText, ...] = Field(default=(), max_length=128)
    declared_locations: tuple[NginxLocationSelector, ...] = Field(default=(), max_length=32)
    sample_uris: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_selector(self) -> "NginxRateLimitSelector":
        if not self.server_names:
            raise ValueError("Rate-limit selectors must declare at least one server_name.")
        for uri in self.sample_uris:
            _validate_nginx_sample_uri(uri)
        if not self.declared_locations and not self.sample_uris:
            return self
        return self


class NginxRequestLimitRequirement(_StrictModel):
    required: bool = True
    accepted_zones: tuple[NginxZoneIdentifier, ...] = Field(default=(), max_length=32)
    require_all_zones: bool = False
    additional_zones: NginxAdditionalZonesMode = "allow"
    burst: NginxIntegerRange | None = None
    delay_mode: NginxRateLimitDelayMode | None = None
    delayed_requests: NginxIntegerRange | None = None
    dry_run: bool | None = None
    allowed_rejection_statuses: tuple[int, ...] = Field(default=(), max_length=16)
    allowed_log_levels: tuple[NginxErrorLogSeverity, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def validate_requirement(self) -> "NginxRequestLimitRequirement":
        _validate_status_codes(self.allowed_rejection_statuses)
        if self.delay_mode == "nodelay" and self.delayed_requests is not None:
            raise ValueError(
                "delay_mode 'nodelay' cannot be combined with delayed_requests."
            )
        if self.delayed_requests is not None and self.burst is None:
            raise ValueError("delayed_requests requires a burst range.")
        if (
            self.delayed_requests is not None
            and self.burst is not None
            and self.delayed_requests.max is not None
            and self.burst.max is not None
            and self.delayed_requests.max > self.burst.max
        ):
            raise ValueError("delayed_requests must not exceed burst bounds.")
        return self


class NginxConnectionLimitRequirement(_StrictModel):
    required: bool = True
    accepted_zones: tuple[NginxZoneIdentifier, ...] = Field(default=(), max_length=32)
    require_all_zones: bool = False
    additional_zones: NginxAdditionalZonesMode = "allow"
    connections: NginxPositiveIntegerRange | None = None
    dry_run: bool | None = None
    allowed_rejection_statuses: tuple[int, ...] = Field(default=(), max_length=16)
    allowed_log_levels: tuple[NginxErrorLogSeverity, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def validate_requirement(self) -> "NginxConnectionLimitRequirement":
        _validate_status_codes(self.allowed_rejection_statuses)
        return self


class NginxRateLimitProfile(_StrictModel):
    profile_id: Identifier
    applies_to: NginxRateLimitSelector
    request: NginxRequestLimitRequirement | None = None
    connection: NginxConnectionLimitRequirement | None = None

    @model_validator(mode="after")
    def validate_non_empty(self) -> "NginxRateLimitProfile":
        if self.request is None and self.connection is None:
            raise ValueError(
                "Rate-limit profiles must declare request and/or connection requirements."
            )
        return self


class NginxRateLimitsPolicy(_StrictModel):
    zone_inventory: NginxRateLimitZoneInventory
    profiles: tuple[NginxRateLimitProfile, ...] = Field(min_length=1, max_length=128)
    unmatched_routes: UnmatchedRouteDisposition = "indeterminate"
    unresolved_internal_redirects: UnmatchedRouteDisposition = "indeterminate"


class NginxResponseHeaderRoute(_StrictModel):
    route_id: Identifier = Field(alias="id")
    server_names: tuple[NonEmptyText, ...] = Field(min_length=1, max_length=128)
    declared_location: NginxLocationSelector | None = None
    sample_uris: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)
    response_kind: NginxResponseKind
    schemes: tuple[NginxResponseScheme, ...] = Field(min_length=1, max_length=2)
    expected_statuses: tuple[int, ...] = Field(min_length=1, max_length=64)
    profile: Identifier

    @model_validator(mode="after")
    def validate_route(self) -> "NginxResponseHeaderRoute":
        if self.declared_location is None and not self.sample_uris:
            raise ValueError(
                "response-header routes must declare a location selector, sample_uris, or both."
            )
        for uri in self.sample_uris:
            _validate_nginx_sample_uri(uri)
        _validate_status_codes(self.expected_statuses)
        return self


class NginxCspEnforcementPolicy(_StrictModel):
    required: bool = False
    baseline_policy: CspBaselinePolicy = "any_enforcing"
    additional_policies: CspAdditionalPoliciesMode = "allow"


class NginxCspScriptAuthorizationPolicy(_StrictModel):
    mode: CspScriptAuthorizationMode
    allowed_nonce_variables: tuple[NginxLogVariable, ...] = Field(default=(), max_length=32)
    allow_static_nonce: bool = False
    allowed_hashes: tuple[NonEmptyText, ...] = Field(default=(), max_length=128)
    allow_host_allowlist_fallback: bool = False
    require_strict_dynamic: bool = False

    @model_validator(mode="after")
    def validate_authorization(self) -> "NginxCspScriptAuthorizationPolicy":
        for raw_hash in self.allowed_hashes:
            _validate_csp_hash_value(raw_hash)
        has_nonce_strategy = bool(self.allowed_nonce_variables or self.allow_static_nonce)
        has_hash_strategy = bool(self.allowed_hashes)
        if self.mode == "nonce" and not has_nonce_strategy:
            raise ValueError(
                "nonce-based script authorization requires allowed_nonce_variables or allow_static_nonce."
            )
        if self.mode == "hash" and not has_hash_strategy:
            raise ValueError("hash-based script authorization requires allowed_hashes.")
        if self.mode in {"nonce_or_hash", "strict_nonce_or_hash"} and not (
            has_nonce_strategy or has_hash_strategy
        ):
            raise ValueError(
                "nonce_or_hash script authorization requires allowed_nonce_variables, allow_static_nonce, or allowed_hashes."
            )
        if self.mode == "strict_nonce_or_hash" and not self.require_strict_dynamic:
            raise ValueError(
                "strict_nonce_or_hash script authorization requires require_strict_dynamic."
            )
        return self


class NginxCspFrameAncestorsPolicy(_StrictModel):
    mode: CspFrameAncestorsMode


class NginxCspReportingPolicy(_StrictModel):
    required: bool = False
    modes: tuple[CspReportingMode, ...] = Field(default=(), max_length=2)
    allowed_groups: tuple[Identifier, ...] = Field(default=(), max_length=32)
    allowed_endpoint_origins: tuple[NonEmptyText, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_reporting(self) -> "NginxCspReportingPolicy":
        if self.required and not self.modes:
            raise ValueError("required CSP reporting must declare at least one reporting mode.")
        return self


class NginxCspReportOnlyPolicy(_StrictModel):
    required: bool = False


class NginxCspProfile(_StrictModel):
    enforcement: NginxCspEnforcementPolicy
    required_directives: dict[NonEmptyText, tuple[NonEmptyText, ...]] = Field(default_factory=dict)
    script_authorization: NginxCspScriptAuthorizationPolicy | None = None
    forbidden_effective_capabilities: tuple[NonEmptyText, ...] = Field(default=(), max_length=32)
    frame_ancestors: NginxCspFrameAncestorsPolicy | None = None
    reporting: NginxCspReportingPolicy | None = None
    report_only: NginxCspReportOnlyPolicy | None = None

    @model_validator(mode="after")
    def validate_csp_profile(self) -> "NginxCspProfile":
        for directive_name, tokens in self.required_directives.items():
            if not _DIRECTIVE_NAME_RE.fullmatch(directive_name):
                raise ValueError(f"Invalid CSP directive name {directive_name!r}.")
            if not tokens:
                raise ValueError(
                    f"CSP required_directives entry {directive_name!r} must contain at least one token."
                )
        return self


class NginxHeaderValuePolicy(_StrictModel):
    required: bool = True
    allowed_values: tuple[NonEmptyText, ...] = Field(min_length=1, max_length=32)
    require_all_expected_statuses: bool = False


class NginxHstsHeaderPolicy(_StrictModel):
    required_on_schemes: tuple[NginxResponseScheme, ...] = Field(min_length=1, max_length=2)
    min_max_age: int = Field(ge=1)
    include_subdomains: bool = False
    require_all_expected_statuses: bool = False


class NginxXFrameOptionsPolicy(_StrictModel):
    mode: SingleValueHeaderMode


class NginxResponseHeaderProfileHeaders(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    referrer_policy: NginxHeaderValuePolicy | None = Field(default=None, alias="Referrer-Policy")
    x_content_type_options: NginxHeaderValuePolicy | None = Field(
        default=None,
        alias="X-Content-Type-Options",
    )
    cross_origin_opener_policy: NginxHeaderValuePolicy | None = Field(
        default=None,
        alias="Cross-Origin-Opener-Policy",
    )
    permissions_policy: NginxHeaderValuePolicy | None = Field(
        default=None,
        alias="Permissions-Policy",
    )
    strict_transport_security: NginxHstsHeaderPolicy | None = Field(
        default=None,
        alias="Strict-Transport-Security",
    )
    x_frame_options: NginxXFrameOptionsPolicy | None = Field(
        default=None,
        alias="X-Frame-Options",
    )


class NginxResponseHeaderProfile(_StrictModel):
    conditional_branches: NginxConditionalBranchDisposition
    csp: NginxCspProfile | None = None
    headers: NginxResponseHeaderProfileHeaders = Field(default_factory=NginxResponseHeaderProfileHeaders)

    @model_validator(mode="after")
    def validate_non_empty(self) -> "NginxResponseHeaderProfile":
        if self.csp is None and not self.headers.model_fields_set:
            raise ValueError("response-header profiles must declare csp and/or headers.")
        return self


class NginxReportingEndpointPolicy(_StrictModel):
    allowed_urls: tuple[NonEmptyText, ...] = Field(min_length=1, max_length=32)


class NginxResponseHeadersPolicy(_StrictModel):
    route_manifest: tuple[NginxResponseHeaderRoute, ...] = Field(min_length=1, max_length=256)
    profiles: dict[Identifier, NginxResponseHeaderProfile] = Field(min_length=1)
    reporting_endpoints: dict[Identifier, NginxReportingEndpointPolicy] = Field(default_factory=dict)
    unmatched_routes: UnmatchedRouteDisposition = "indeterminate"
    unresolved_internal_redirects: UnmatchedRouteDisposition = "indeterminate"


class NginxPolicy(_StrictModel):
    reverse_proxy_headers: NginxReverseProxyHeadersPolicy | None = None
    logging: NginxLoggingPolicy | None = None
    sensitive_locations: NginxSensitiveLocationsPolicy | None = None
    rate_limits: NginxRateLimitsPolicy | None = None
    response_headers: NginxResponseHeadersPolicy | None = None


class TLSInventoryAttestation(_StrictModel):
    asserted_by: NonEmptyText
    asserted_at: datetime
    basis: NonEmptyText


class TLSTrustPolicy(_StrictModel):
    mode: TLSTrustMode
    ca_path: NonEmptyText | None = None

    @model_validator(mode="after")
    def validate_mode(self) -> "TLSTrustPolicy":
        if self.mode == "custom" and self.ca_path is None:
            raise ValueError("Custom TLS trust mode requires ca_path.")
        if self.mode == "system" and self.ca_path is not None:
            raise ValueError("System TLS trust mode cannot declare ca_path.")
        return self


class TLSNotApplicableDeclaration(_StrictModel):
    reason: NonEmptyText


class TLSInventoryEntry(_StrictModel):
    entry_id: Identifier = Field(alias="id")
    connect_host: NonEmptyText
    connect_port: int = Field(ge=1, le=65535)
    sni_name: NonEmptyText | None = None
    http_host: NonEmptyText | None = None
    path: NonEmptyText = "/"
    expected_certificate_names: tuple[NonEmptyText, ...] = Field(
        default=(),
        max_length=128,
    )
    not_applicable: dict[TLSRequiredEvidence, TLSNotApplicableDeclaration] = Field(
        default_factory=dict,
    )

    @model_validator(mode="before")
    @classmethod
    def default_http_host(cls, value):
        if not isinstance(value, dict):
            return value
        normalized = dict(value)
        if "http_host" not in normalized:
            normalized["http_host"] = normalized.get("sni_name")
        return normalized

    @field_validator("connect_host", "sni_name", "http_host", mode="before")
    @classmethod
    def normalize_host_identity(cls, value):
        if value is None:
            return None
        return _normalize_tls_identity(value)

    @field_validator("expected_certificate_names", mode="before")
    @classmethod
    def normalize_expected_certificate_names(cls, value):
        if value is None:
            return value
        if not isinstance(value, (list, tuple)):
            raise ValueError(
                "expected_certificate_names must be a list of TLS identities."
            )
        return tuple(
            _normalize_tls_identity(name, allow_wildcard=True)
            for name in value
        )

    @model_validator(mode="after")
    def validate_entry(self) -> "TLSInventoryEntry":
        _validate_tls_inventory_path(self.path)
        if (
            self.sni_name is None
            and "certificate_name" not in self.not_applicable
        ):
            raise ValueError(
                "TLS inventory entries without sni_name must declare "
                "certificate_name not-applicable with a reason."
            )
        return self


class TLSInventory(_StrictModel):
    inventory_id: Identifier = Field(alias="id")
    environment: NonEmptyText | None = None
    declared_complete: bool = False
    completeness_attestation: TLSInventoryAttestation | None = None
    trust: TLSTrustPolicy
    required_evidence: tuple[TLSRequiredEvidence, ...] = Field(
        min_length=1,
        max_length=16,
    )
    entries: tuple[TLSInventoryEntry, ...] = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def validate_inventory(self) -> "TLSInventory":
        if self.declared_complete and self.completeness_attestation is None:
            raise ValueError(
                "declared_complete TLS inventories require completeness attestation."
            )
        if len(set(self.required_evidence)) != len(self.required_evidence):
            raise ValueError("TLS inventory required_evidence values must be unique.")

        seen_entry_ids: set[str] = set()
        seen_identities: set[tuple[str, int, str | None, str | None]] = set()
        for entry in self.entries:
            if entry.entry_id in seen_entry_ids:
                raise ValueError(
                    f"TLS inventory repeats entry id {entry.entry_id!r}."
                )
            seen_entry_ids.add(entry.entry_id)

            identity = (
                entry.connect_host,
                entry.connect_port,
                entry.sni_name,
                entry.http_host,
            )
            if identity in seen_identities:
                raise ValueError(
                    "TLS inventory entries must have unique normalized identity tuples."
                )
            seen_identities.add(identity)
        return self


class ExternalPolicy(_StrictModel):
    tls_inventories: tuple[TLSInventory, ...] = Field(
        default=(),
        max_length=128,
    )

    @model_validator(mode="after")
    def validate_inventory_ids(self) -> "ExternalPolicy":
        inventory_ids = [inventory.inventory_id for inventory in self.tls_inventories]
        if len(set(inventory_ids)) != len(inventory_ids):
            raise ValueError("external.tls_inventories ids must be unique.")
        return self


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
    external: ExternalPolicy | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
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
    external: ExternalPolicy | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )


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
    "CspAdditionalPoliciesMode",
    "CspBaselinePolicy",
    "CspFrameAncestorsMode",
    "CspReportingMode",
    "CspScriptAuthorizationMode",
    "ControlPolicy",
    "EvidenceExpectation",
    "ExternalPolicy",
    "HeaderExpression",
    "HeaderName",
    "LoadedPolicyProvenance",
    "NginxAccessDestinationEntry",
    "NginxAccessDestinationKind",
    "NginxAccessDestinationPolicy",
    "NginxAdditionalZonesMode",
    "NginxAccessFormatPolicy",
    "NginxAccessLoggingPolicy",
    "NginxByteSize",
    "NginxConditionMode",
    "NginxConditionalBranchDisposition",
    "NginxConnectionLimitRequirement",
    "NginxConnectionZoneInventoryEntry",
    "NginxCspEnforcementPolicy",
    "NginxCspFrameAncestorsPolicy",
    "NginxCspProfile",
    "NginxCspReportOnlyPolicy",
    "NginxCspReportingPolicy",
    "NginxCspScriptAuthorizationPolicy",
    "NginxErrorDestinationKind",
    "NginxErrorDestinationPolicy",
    "NginxErrorLogSeverity",
    "NginxErrorLoggingPolicy",
    "NginxErrorThresholdPolicy",
    "NginxEscapeMode",
    "NginxFieldGroupName",
    "NginxIpAllowlistRequirement",
    "NginxIntegerRange",
    "NginxLocationSelector",
    "NginxLocationSelectorModifier",
    "NginxLoggingConditionalPolicy",
    "NginxLoggingPolicy",
    "NginxLoggingProfile",
    "NginxLoggingSelector",
    "NginxLogVariable",
    "NginxPolicy",
    "NginxPositiveIntegerRange",
    "NginxRateLimitDelayMode",
    "NginxRateLimitProfile",
    "NginxRateLimitSelector",
    "NginxRateLimitZoneInventory",
    "NginxRateLimitsPolicy",
    "NginxRequestLimitRequirement",
    "NginxRequestRate",
    "NginxRequestRateRange",
    "NginxReportingEndpointPolicy",
    "NginxRequestZoneInventoryEntry",
    "NginxResponseHeaderProfile",
    "NginxResponseHeaderProfileHeaders",
    "NginxResponseHeaderRoute",
    "NginxResponseHeadersPolicy",
    "NginxResponseKind",
    "NginxResponseScheme",
    "NginxReverseProxyHeadersPolicy",
    "NginxSensitiveLocationEntry",
    "NginxSensitiveLocationExposure",
    "NginxSensitiveLocationKind",
    "NginxSensitiveLocationRequirement",
    "NginxSensitiveLocationsPolicy",
    "NginxHeaderValuePolicy",
    "NginxHstsHeaderPolicy",
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
    "SingleValueHeaderMode",
    "SourcePolicy",
    "TargetSelector",
    "TLSInventory",
    "TLSInventoryAttestation",
    "TLSInventoryEntry",
    "TLSNotApplicableDeclaration",
    "TLSObservationRequirement",
    "TLSRequiredEvidence",
    "TLSTrustMode",
    "TLSTrustPolicy",
    "UnmatchedRouteDisposition",
    "UpstreamFamily",
]


def _normalize_nginx_variable(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith("${") and stripped.endswith("}"):
        return f"${stripped[2:-1]}"
    return stripped


def _normalize_tls_identity(
    value: str,
    *,
    allow_wildcard: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValueError("TLS identities must be strings.")
    normalized = value.strip()
    wildcard = normalized.startswith("*.")
    if wildcard:
        if not allow_wildcard:
            raise ValueError(f"TLS identity {value!r} cannot be a wildcard.")
        normalized = normalized[2:]
    elif "*" in normalized:
        raise ValueError(f"TLS identity {value!r} contains an invalid wildcard.")

    ip_candidate = normalized
    if ip_candidate.startswith("[") and ip_candidate.endswith("]"):
        ip_candidate = ip_candidate[1:-1]
    try:
        ip_value = ipaddress.ip_address(ip_candidate)
    except ValueError:
        dns_name = normalized.rstrip(".")
        if not dns_name or any(not label for label in dns_name.split(".")):
            raise ValueError(f"Invalid DNS identity {value!r}.")
        try:
            ascii_name = dns_name.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(f"Invalid DNS identity {value!r}.") from exc
        if len(ascii_name) > 253 or any(
            len(label) > 63
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            is None
            for label in ascii_name.split(".")
        ):
            raise ValueError(f"Invalid DNS identity {value!r}.")
        normalized_identity = ascii_name
    else:
        normalized_identity = ip_value.compressed

    if wildcard:
        return f"*.{normalized_identity}"
    return normalized_identity


def _validate_tls_inventory_path(value: str) -> None:
    parts = urlsplit(value)
    if (
        parts.scheme
        or parts.netloc
        or parts.query
        or parts.fragment
        or not value.startswith("/")
    ):
        raise ValueError(
            f"TLS inventory path {value!r} must be an absolute path without scheme, host, query, or fragment."
        )


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
    _validate_nginx_sample_uri(value)
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or parts.query or parts.fragment:
        raise ValueError(
            f"Sensitive location sample URI {value!r} must be an absolute path without scheme, host, query, or fragment."
        )
    if value != _normalize_sensitive_location_uri(value):
        raise ValueError(
            f"Sensitive location sample URI {value!r} must already be normalized for static matching."
        )


def _validate_nginx_sample_uri(value: str) -> None:
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or parts.query or parts.fragment:
        raise ValueError(
            f"Nginx sample URI {value!r} must be an absolute path without scheme, host, query, or fragment."
        )
    if not value.startswith("/"):
        raise ValueError(f"Nginx sample URI {value!r} must start with '/'.")


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


def _parse_nginx_size(value: str) -> int:
    normalized = value.strip().lower()
    match = re.fullmatch(r"(?P<number>\d+)(?P<unit>[kmg])?", normalized)
    if match is None:
        raise ValueError(f"Invalid Nginx size value {value!r}.")
    number = int(match.group("number"), 10)
    unit = match.group("unit")
    multiplier = {
        None: 1,
        "k": 1024,
        "m": 1024 * 1024,
        "g": 1024 * 1024 * 1024,
    }[unit]
    return number * multiplier


def _parse_request_rate(value: str) -> tuple[int, int]:
    normalized = value.strip().lower()
    match = re.fullmatch(r"(?P<number>\d+)r/(?P<unit>s|m)", normalized)
    if match is None:
        raise ValueError(f"Invalid Nginx request rate {value!r}.")
    number = int(match.group("number"), 10)
    period_seconds = 1 if match.group("unit") == "s" else 60
    return number, period_seconds


def _request_rate_ratio(value: NginxRequestRate):
    return Fraction(value.requests, value.period_seconds)


def _validate_status_codes(values: tuple[int, ...]) -> None:
    for status in values:
        if status < 100 or status > 599:
            raise ValueError(f"Invalid HTTP status code {status!r}.")


def _validate_csp_hash_value(value: str) -> None:
    match = _CSP_HASH_RE.match(value.strip())
    if match is None:
        raise ValueError(f"Invalid CSP hash source {value!r}.")
    hash_value = match.group("quoted_value") or match.group("plain_value")
    if hash_value is None or not _is_valid_csp_base64_value(hash_value):
        raise ValueError(f"Invalid CSP hash source {value!r}.")


def _is_valid_csp_base64_value(value: str) -> bool:
    if not value or len(value) % 4 == 1:
        return False
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    try:
        base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return False
    return True


NginxSensitiveLocationRequirement.model_rebuild()
