"""Risk-factor profiles used to explain rule severity decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from webconf_audit.models import Severity

Impact = Literal["confidentiality", "integrity", "availability"]
Exposure = Literal["external", "mixed", "local"]
Exploitability = Literal["direct", "conditional", "indirect"]
Confidence = Literal["high", "medium", "low"]
ContextDependency = Literal["low", "medium", "high"]

IMPACTS: frozenset[Impact] = frozenset(
    {"confidentiality", "integrity", "availability"}
)
EXPOSURES: frozenset[Exposure] = frozenset({"external", "mixed", "local"})
EXPLOITABILITIES: frozenset[Exploitability] = frozenset(
    {"direct", "conditional", "indirect"}
)
CONFIDENCES: frozenset[Confidence] = frozenset({"high", "medium", "low"})
CONTEXT_DEPENDENCIES: frozenset[ContextDependency] = frozenset(
    {"low", "medium", "high"}
)
PROJECT_RULE_PREFIXES = (
    "universal.",
    "nginx.",
    "apache.",
    "lighttpd.",
    "iis.",
    "external.",
)
_SEVERITY_RANK: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_RANK_SEVERITY: dict[int, Severity] = {
    rank: severity for severity, rank in _SEVERITY_RANK.items()
}
_CONFIDENTIALITY_ONLY_RULE_KEYS = frozenset(
    {
        "request_filtering_remove_server_header_disabled",
    }
)
_DIRECT_EXPLOITABILITY_RULE_KEYS = frozenset(
    {
        "ssl_conf_command_unsafe_renegotiation_enabled",
    }
)
_CONDITIONAL_EXPLOITABILITY_RULE_KEYS = frozenset(
    {
        "ssl_protocol_policy_missing_or_weak",
        "ssl_weak_cipher_strength",
    }
)
_INDIRECT_EXPLOITABILITY_RULE_KEYS = frozenset(
    {
        "mod_webdav_enabled",
    }
)
_HIGH_CONFIDENCE_RULE_KEYS = frozenset(
    {
        "ssl_conf_command_unsafe_renegotiation_enabled",
    }
)
_HIGH_CONTEXT_RULE_KEYS = frozenset(
    {
        "mod_webdav_enabled",
        "request_filtering_remove_server_header_disabled",
        "ssl_weak_cipher_strength",
    }
)
_LOW_CONTEXT_RULE_KEYS = frozenset(
    {
        "ssl_conf_command_unsafe_renegotiation_enabled",
    }
)

_CONFIDENTIALITY_TOKENS = (
    "auth",
    "alias",
    "backup",
    "certificate",
    "cipher",
    "config",
    "cookie",
    "credential",
    "directory listing",
    "directory_browse",
    "disclos",
    "etag",
    "git",
    "hsts",
    "https",
    "metadata",
    "machine_key",
    "machinekey",
    "private",
    "secret",
    "sensitive",
    "server_info",
    "server_status",
    "ssl",
    "svn",
    "tls",
    "trace",
    "traversal",
    "version",
    "vcs",
)
_INTEGRITY_TOKENS = (
    "allow",
    "alias",
    "anonymous",
    "cgi",
    "content-security-policy",
    "content-type",
    "cors",
    "csp",
    "crlf",
    "dangerous method",
    "debug",
    "exec",
    "frame",
    "machine_key",
    "machinekey",
    "method",
    "permissions",
    "proxy",
    "referrer",
    "request_filtering",
    "script",
    "sri",
    "ssrf",
    "traversal",
    "upload",
    "webdav",
    "write",
    "x_content_type",
    "x_frame",
)
_AVAILABILITY_TOKENS = (
    "body_size",
    "buffer",
    "connection",
    "keepalive",
    "limit",
    "rate",
    "request_body",
    "request_line",
    "timeout",
)
_DIRECT_TOKENS = (
    "alias_without_trailing_slash",
    "allow_all_with_deny_all",
    "anonymous_auth",
    "auth_basic_over_http",
    "autoindex",
    "basic_auth_over_http",
    "basic_auth_without_ssl",
    "cgi_handler_enabled",
    "compilation_debug_enabled",
    "crlf",
    "dangerous_http_methods",
    "debug",
    "directory_browse_enabled",
    "directory_listing_enabled",
    "git_metadata_exposed",
    "no tls configuration",
    "non-tls listener",
    "over http",
    "private_key",
    "proxy_pass_user_controlled",
    "ssl_insecure_renegotiation",
    "ssl_not_required",
    "trace",
    "tls_required_for_authenticated_routes",
    "unsafe_renegotiation",
    "weak_cipher",
    "weak_ssl_cipher",
    "weak_ssl_protocols",
    "without ssl",
    "without tls",
    "webdav",
)
_INDIRECT_TOKENS = (
    "base-uri",
    "cert_chain_length_unusual",
    "default_welcome",
    "disclos",
    "format_review",
    "listen_on_all_interfaces",
    "log",
    "merge_slashes",
    "missing_access_log",
    "missing_content_security_policy",
    "missing_error_log",
    "missing_frame_ancestors",
    "missing_http2_on_tls_listener",
    "missing_log_format",
    "missing_permissions_policy",
    "missing_referrer_policy",
    "missing_reporting_endpoint",
    "missing_x_",
    "not_observed",
    "options_method",
    "object-src",
    "policy_missing",
    "referrer_policy_missing",
    "review",
    "server_tokens",
    "signature",
    "tls 1.3 not supported",
    "version",
    "x_content_type_options_missing",
    "x_frame_options_missing",
    "x_powered",
)
_EXTERNAL_TOKENS = (
    "auth",
    "alias",
    "allow",
    "autoindex",
    "cgi",
    "cookie",
    "cors",
    "directory",
    "exposed",
    "header",
    "host",
    "identification",
    "http",
    "https",
    "listen",
    "machine_key",
    "machinekey",
    "merge_slashes",
    "method",
    "proxy",
    "public",
    "redirect",
    "return",
    "rewrite",
    "sensitive",
    "server_signature",
    "server_tokens",
    "server identification",
    "status",
    "tls",
    "traversal",
    "upload",
    "webdav",
)
_HIGH_CONTEXT_TOKENS = (
    "access_log",
    "buffer",
    "content_security_policy",
    "csp",
    "format_review",
    "log_format",
    "keepalive",
    "limit",
    "listen_on_all_interfaces",
    "log",
    "merge_slashes",
    "missing_http2_on_tls_listener",
    "modsecurity",
    "permissions_policy",
    "rate",
    "referrer_policy",
    "server_signature",
    "timeout",
    "waf",
)
_LOW_CONTEXT_TOKENS = (
    "alias_without_trailing_slash",
    "anonymous_auth",
    "auth_basic_over_http",
    "basic_auth_over_http",
    "certificate_expired",
    "crlf",
    "debug",
    "directory_browse_enabled",
    "git_metadata_exposed",
    "private_key",
    "ssl_insecure_renegotiation",
    "tls_required_for_authenticated_routes",
    "trace",
    "weak_cipher",
    "weak_ssl_cipher",
    "weak_ssl_protocols",
    "webdav_write",
)


@dataclass(frozen=True)
class SeverityProfile:
    """Risk factors used to justify a rule's default severity."""

    impact: tuple[Impact, ...]
    exposure: Exposure
    exploitability: Exploitability
    confidence: Confidence
    context_dependency: ContextDependency

    def as_payload(self) -> dict[str, object]:
        """Return a stable JSON-ready representation for rule catalog output."""
        return {
            "impact": list(self.impact),
            "exposure": self.exposure,
            "exploitability": self.exploitability,
            "confidence": self.confidence,
            "context_dependency": self.context_dependency,
        }


def infer_severity_profile(
    *,
    rule_id: str,
    title: str,
    description: str,
    category: str,
    input_kind: str,
    tags: tuple[str, ...],
) -> SeverityProfile:
    """Infer a default severity profile from stable rule metadata."""
    rule_key = rule_id.rsplit(".", 1)[-1]
    text = _analysis_text(rule_id, title, description, tags)
    return SeverityProfile(
        impact=_infer_impact(rule_key, text, tags),
        exposure=_infer_exposure(text, category, input_kind),
        exploitability=_infer_exploitability(rule_key, text, tags),
        confidence=_infer_confidence(rule_key, text, tags),
        context_dependency=_infer_context_dependency(rule_key, text, tags),
    )


def calibrate_severity(
    *,
    rule_id: str,
    declared_severity: Severity,
    profile: SeverityProfile,
    tags: tuple[str, ...],
) -> Severity:
    """Return the default severity calibrated from the rule risk profile."""
    if not is_project_rule(rule_id):
        return declared_severity
    if "policy-review" in tags:
        return "info"
    if "network" in tags and profile.exploitability == "indirect":
        return "info"
    if profile.confidence == "low" and profile.exploitability == "indirect":
        return "info"

    severity = _severity_from_score(_severity_score(profile))
    if profile.confidence == "low":
        severity = _min_severity(severity, "low")
    if profile.exploitability == "indirect" and len(profile.impact) == 1:
        severity = _min_severity(severity, "low")
    if profile.context_dependency == "high" and severity == "high":
        severity = "medium"
    if profile.exploitability == "indirect" and profile.context_dependency == "high":
        severity = _min_severity(severity, "low")
    if profile.exposure == "local" and profile.exploitability == "indirect":
        severity = "info"
    return severity


def is_project_rule(rule_id: str) -> bool:
    """Return whether a rule belongs to the built-in project catalog."""
    return rule_id.startswith(PROJECT_RULE_PREFIXES)


def _severity_score(profile: SeverityProfile) -> int:
    impact = min(len(profile.impact), 2)
    exposure = {"local": 0, "mixed": 2, "external": 2}[profile.exposure]
    exploitability = {"indirect": 0, "conditional": 2, "direct": 3}[
        profile.exploitability
    ]
    confidence = {"low": -1, "medium": 0, "high": 1}[profile.confidence]
    context = {"high": -1, "medium": 0, "low": 1}[profile.context_dependency]
    return impact + exposure + exploitability + confidence + context


def _severity_from_score(score: int) -> Severity:
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 2:
        return "low"
    return "info"


def _min_severity(first: Severity, second: Severity) -> Severity:
    return _RANK_SEVERITY[min(_SEVERITY_RANK[first], _SEVERITY_RANK[second])]


def _analysis_text(
    rule_id: str,
    title: str,
    description: str,
    tags: tuple[str, ...],
) -> str:
    return " ".join((rule_id, title, description, " ".join(tags))).lower()


def _infer_impact(
    rule_key: str, text: str, tags: tuple[str, ...]
) -> tuple[Impact, ...]:
    if rule_key in _CONFIDENTIALITY_ONLY_RULE_KEYS:
        return ("confidentiality",)

    impact: list[Impact] = []
    if _has_any(text, _CONFIDENTIALITY_TOKENS) or "tls" in tags:
        impact.append("confidentiality")
    if _has_any(text, _INTEGRITY_TOKENS) or "headers" in tags:
        impact.append("integrity")
    if _has_any(text, _AVAILABILITY_TOKENS) or "rate-limit" in tags:
        impact.append("availability")
    if not impact:
        impact.append("confidentiality")
    return tuple(dict.fromkeys(impact))


def _infer_exposure(text: str, category: str, input_kind: str) -> Exposure:
    if category == "external" or input_kind == "probe":
        return "external"
    if _has_any(text, _EXTERNAL_TOKENS):
        return "mixed"
    return "local"


def _infer_exploitability(
    rule_key: str,
    text: str,
    tags: tuple[str, ...],
) -> Exploitability:
    if "policy-review" in tags:
        return "indirect"
    if rule_key in _DIRECT_EXPLOITABILITY_RULE_KEYS:
        return "direct"
    if rule_key in _CONDITIONAL_EXPLOITABILITY_RULE_KEYS:
        return "conditional"
    if rule_key in _INDIRECT_EXPLOITABILITY_RULE_KEYS:
        return "indirect"
    if _has_any(text, _DIRECT_TOKENS):
        return "direct"
    if _has_any(text, _INDIRECT_TOKENS):
        return "indirect"
    return "conditional"


def _infer_confidence(rule_key: str, text: str, tags: tuple[str, ...]) -> Confidence:
    if "policy-review" in tags or "review" in text or "semantics" in text:
        return "low"
    if rule_key in _HIGH_CONFIDENCE_RULE_KEYS:
        return "high"
    if "missing_" in text or "not_configured" in text or "unsafe" in text:
        return "medium"
    return "high"


def _infer_context_dependency(
    rule_key: str,
    text: str,
    tags: tuple[str, ...],
) -> ContextDependency:
    if rule_key in _HIGH_CONTEXT_RULE_KEYS:
        return "high"
    if rule_key in _LOW_CONTEXT_RULE_KEYS:
        return "low"
    if "policy-review" in tags or _has_any(text, _HIGH_CONTEXT_TOKENS):
        return "high"
    if _has_any(text, _LOW_CONTEXT_TOKENS):
        return "low"
    return "medium"


def _has_any(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


__all__ = [
    "CONFIDENCES",
    "CONTEXT_DEPENDENCIES",
    "EXPLOITABILITIES",
    "EXPOSURES",
    "IMPACTS",
    "PROJECT_RULE_PREFIXES",
    "Confidence",
    "ContextDependency",
    "Exploitability",
    "Exposure",
    "Impact",
    "SeverityProfile",
    "calibrate_severity",
    "infer_severity_profile",
    "is_project_rule",
]
