"""Universal rules for missing security headers.

Covers:
- universal.missing_x_content_type_options
- universal.missing_x_frame_options
- universal.missing_content_security_policy
- universal.missing_referrer_policy
"""

from __future__ import annotations

from collections.abc import Callable

from webconf_audit.header_policy import (
    content_security_policy_has_frame_ancestors,
    permissions_policy_is_safe,
    referrer_policy_is_safe,
)
from webconf_audit.local.normalized import (
    NormalizedConfig,
    NormalizedScope,
    NormalizedSecurityHeader,
    SourceRef,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

HeaderRule = tuple[str, str, str, str | None]

_HEADER_RULES: dict[str, HeaderRule] = {
    "universal.missing_x_content_type_options": (
        "x-content-type-options",
        "X-Content-Type-Options header missing or incorrect",
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
        "nosniff",
    ),
    "universal.missing_x_frame_options": (
        "x-frame-options",
        "X-Frame-Options header missing",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
        None,
    ),
    "universal.missing_content_security_policy": (
        "content-security-policy",
        "Content-Security-Policy header missing",
        "Add a Content-Security-Policy header to mitigate XSS and injection attacks.",
        None,
    ),
    "universal.missing_referrer_policy": (
        "referrer-policy",
        "Referrer-Policy header missing",
        "Add a Referrer-Policy header (e.g. 'strict-origin-when-cross-origin').",
        None,
    ),
}


@rule(
    rule_id="universal.missing_x_content_type_options",
    title="X-Content-Type-Options header missing or incorrect",
    severity="low",
    description="Scope does not set the X-Content-Type-Options response header with value 'nosniff'.",
    recommendation="Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
    category="universal",
    input_kind="normalized",
    tags=("headers",),
    standards=(
        cwe(693),
        owasp_top10_2021("A05:2021"),
        asvs_5("3.4.4"),
    ),
    order=104,
)
def check_x_content_type_options(config: NormalizedConfig) -> list[Finding]:
    rule_id = "universal.missing_x_content_type_options"
    return _check_header(config, rule_id, *_HEADER_RULES[rule_id])


@rule(
    rule_id="universal.missing_x_frame_options",
    title="X-Frame-Options header missing",
    severity="low",
    description="Scope does not set the X-Frame-Options response header.",
    recommendation="Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
    category="universal",
    input_kind="normalized",
    tags=("headers",),
    standards=(
        cwe(1021),
        owasp_top10_2021("A05:2021"),
    ),
    order=105,
)
def check_x_frame_options(config: NormalizedConfig) -> list[Finding]:
    rule_id = "universal.missing_x_frame_options"
    return _check_header(
        config,
        rule_id,
        *_HEADER_RULES[rule_id],
        equivalent_header_name="content-security-policy",
        is_equivalent_value=content_security_policy_has_frame_ancestors,
    )


@rule(
    rule_id="universal.missing_content_security_policy",
    title="Content-Security-Policy header missing",
    severity="low",
    description="Scope does not set the Content-Security-Policy response header.",
    recommendation="Add a Content-Security-Policy header to mitigate XSS and injection attacks.",
    category="universal",
    input_kind="normalized",
    tags=("headers",),
    standards=(
        cwe(693),
        owasp_top10_2021("A05:2021"),
        asvs_5("3.4.3", coverage="partial", note="Presence only."),
    ),
    order=106,
)
def check_content_security_policy(config: NormalizedConfig) -> list[Finding]:
    rule_id = "universal.missing_content_security_policy"
    return _check_header(config, rule_id, *_HEADER_RULES[rule_id])


@rule(
    rule_id="universal.missing_referrer_policy",
    title="Referrer-Policy header missing",
    severity="low",
    description="Scope does not set the Referrer-Policy response header.",
    recommendation="Add a Referrer-Policy header (e.g. 'strict-origin-when-cross-origin').",
    category="universal",
    input_kind="normalized",
    tags=("headers",),
    standards=(
        owasp_top10_2021("A05:2021"),
        asvs_5("3.4.5"),
    ),
    order=107,
)
def check_referrer_policy(config: NormalizedConfig) -> list[Finding]:
    rule_id = "universal.missing_referrer_policy"
    return _check_header(config, rule_id, *_HEADER_RULES[rule_id])


@rule(
    rule_id="universal.referrer_policy_unsafe",
    title="Referrer-Policy header is weak",
    severity="low",
    description="Scope sets Referrer-Policy to a weak or unrecognized value.",
    recommendation=(
        "Use 'Referrer-Policy: strict-origin-when-cross-origin' or "
        "'Referrer-Policy: no-referrer'."
    ),
    category="universal",
    input_kind="normalized",
    tags=("headers",),
    standards=(
        owasp_top10_2021("A05:2021"),
        asvs_5("3.4.5"),
    ),
    order=112,
)
def check_referrer_policy_unsafe(config: NormalizedConfig) -> list[Finding]:
    return _check_unsafe_header(
        config,
        rule_id="universal.referrer_policy_unsafe",
        header_name="referrer-policy",
        title="Referrer-Policy header is weak",
        description="Scope sets Referrer-Policy to a weak or unrecognized value.",
        recommendation=(
            "Use 'Referrer-Policy: strict-origin-when-cross-origin' or "
            "'Referrer-Policy: no-referrer'."
        ),
        is_safe_value=referrer_policy_is_safe,
    )


@rule(
    rule_id="universal.permissions_policy_unsafe",
    title="Permissions-Policy header is overly broad",
    severity="low",
    description="Scope sets Permissions-Policy to an empty or overly broad value.",
    recommendation=(
        "Use a least-privilege Permissions-Policy allowlist and avoid wildcard "
        "feature grants."
    ),
    category="universal",
    input_kind="normalized",
    tags=("headers",),
    standards=(
        owasp_top10_2021("A05:2021"),
        asvs_5(
            "3.4.6",
            coverage="related",
            note=(
                "Permissions-Policy is related response-header posture and does "
                "not directly prove the ASVS framing requirement."
            ),
        ),
    ),
    order=113,
)
def check_permissions_policy_unsafe(config: NormalizedConfig) -> list[Finding]:
    return _check_unsafe_header(
        config,
        rule_id="universal.permissions_policy_unsafe",
        header_name="permissions-policy",
        title="Permissions-Policy header is overly broad",
        description="Scope sets Permissions-Policy to an empty or overly broad value.",
        recommendation=(
            "Use a least-privilege Permissions-Policy allowlist and avoid wildcard "
            "feature grants."
        ),
        is_safe_value=permissions_policy_is_safe,
    )


def _check_header(
    config: NormalizedConfig,
    rule_id: str,
    header_name: str,
    title: str,
    recommendation: str,
    required_value: str | None = None,
    *,
    equivalent_header_name: str | None = None,
    is_equivalent_value: Callable[[str | None], bool] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for scope in config.scopes:
        if not _scope_is_auditable(scope):
            continue
        if (
            equivalent_header_name is not None
            and is_equivalent_value is not None
            and _has_safe_header(scope, equivalent_header_name, is_equivalent_value)
        ):
            continue
        if _has_header(scope, header_name, required_value):
            continue
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity="low",
                description=(
                    f"Scope '{scope.scope_name or '(unnamed)'}' does not set "
                    f"the {header_name} response header"
                    + (f" with value '{required_value}'" if required_value else "")
                    + "."
                ),
                recommendation=recommendation,
                location=_scope_location(scope, config),
                metadata={
                    "scope_name": scope.scope_name,
                    "server_type": config.server_type,
                },
            )
        )
    return findings


def _check_unsafe_header(
    config: NormalizedConfig,
    *,
    rule_id: str,
    header_name: str,
    title: str,
    description: str,
    recommendation: str,
    is_safe_value: Callable[[str | None], bool],
) -> list[Finding]:
    findings: list[Finding] = []
    for scope in config.scopes:
        if not _scope_is_auditable(scope):
            continue
        for header in scope.security_headers:
            if header.name != header_name or is_safe_value(header.value):
                continue
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity="low",
                    description=(
                        f"{description} Scope '{scope.scope_name or '(unnamed)'}' "
                        f"configured value: {header.value or '<missing value>'}."
                    ),
                    recommendation=recommendation,
                    location=_header_location(header, scope, config),
                    metadata={
                        "scope_name": scope.scope_name,
                        "server_type": config.server_type,
                    },
                )
            )
    return findings


def _scope_is_auditable(scope: NormalizedScope) -> bool:
    """Decide whether a scope should be checked for missing headers.

    A scope is auditable when it has security headers (even if it's missing
    some) or listen points — these indicate an active web-serving context.
    """
    return bool(scope.security_headers or scope.listen_points)


def _has_header(
    scope: NormalizedScope,
    name: str,
    required_value: str | None = None,
) -> bool:
    for h in scope.security_headers:
        if h.name != name:
            continue
        if required_value is None:
            return True
        # Value check: case-insensitive, strip quotes.
        if h.value and h.value.strip().strip('"').strip("'").lower() == required_value.lower():
            return True
    return False


def _has_safe_header(
    scope: NormalizedScope,
    name: str,
    is_safe_value: Callable[[str | None], bool],
) -> bool:
    return any(
        header.name == name and is_safe_value(header.value)
        for header in scope.security_headers
    )


def _header_location(
    header: NormalizedSecurityHeader,
    scope: NormalizedScope,
    config: NormalizedConfig,
) -> SourceLocation:
    if header.source is None:
        return _scope_location(scope, config)
    return _source_location(header.source, config)


def _scope_location(
    scope: NormalizedScope,
    config: NormalizedConfig,
) -> SourceLocation:
    if scope.listen_points:
        src = scope.listen_points[0].source
    elif scope.tls:
        src = scope.tls.source
    elif scope.access_policy:
        src = scope.access_policy.source
    elif scope.security_headers:
        src = scope.security_headers[0].source
    else:
        return SourceLocation(
            mode="local",
            kind="check",
            target=scope.scope_name or config.server_type,
            details=f"server_type={config.server_type}",
        )
    return _source_location(src, config)


def _source_location(src: SourceRef, config: NormalizedConfig) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="xml" if src.xml_path else "file",
        file_path=src.file_path,
        line=src.line,
        xml_path=src.xml_path,
        details=f"server_type={config.server_type}",
    )
