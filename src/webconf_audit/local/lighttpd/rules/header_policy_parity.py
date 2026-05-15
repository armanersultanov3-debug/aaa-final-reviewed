"""lighttpd.missing_content_security_policy -- Content-Security-Policy header missing."""

from __future__ import annotations

from collections.abc import Callable

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.header_policy import (
    permissions_policy_is_safe,
    referrer_policy_is_safe,
)
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst, LighttpdSourceSpan
from webconf_audit.local.lighttpd.rules.header_tuple_utils import iter_header_values
from webconf_audit.local.lighttpd.rules.redirect_scope_utils import (
    is_redirect_only_config,
)
from webconf_audit.local.lighttpd.rules.rule_utils import default_location
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule


@rule(
    rule_id="lighttpd.missing_content_security_policy",
    title="Content-Security-Policy header missing",
    severity="low",
    description="No Content-Security-Policy header is configured via setenv.add-response-header.",
    recommendation="Add a restrictive Content-Security-Policy header.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers",),
    order=433,
)
def find_missing_content_security_policy(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _missing_header(
        config_ast,
        "Content-Security-Policy",
        find_missing_content_security_policy,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.missing_x_frame_options",
    title="X-Frame-Options header missing",
    severity="low",
    description="No X-Frame-Options header is configured via setenv.add-response-header.",
    recommendation="Add X-Frame-Options: DENY or SAMEORIGIN, or enforce frame-ancestors via CSP.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers",),
    order=434,
)
def find_missing_x_frame_options(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _missing_header(
        config_ast,
        "X-Frame-Options",
        find_missing_x_frame_options,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.missing_referrer_policy",
    title="Referrer-Policy header missing",
    severity="low",
    description="No Referrer-Policy header is configured via setenv.add-response-header.",
    recommendation="Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers",),
    order=435,
)
def find_missing_referrer_policy(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _missing_header(
        config_ast,
        "Referrer-Policy",
        find_missing_referrer_policy,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.referrer_policy_unsafe",
    title="Referrer-Policy header is weak",
    severity="low",
    description="Lighttpd sets Referrer-Policy to a weak or unrecognized value.",
    recommendation="Use Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers",),
    order=436,
)
def find_referrer_policy_unsafe(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _unsafe_header(
        config_ast,
        "Referrer-Policy",
        referrer_policy_is_safe,
        find_referrer_policy_unsafe,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.missing_permissions_policy",
    title="Permissions-Policy header missing",
    severity="low",
    description="No Permissions-Policy header is configured via setenv.add-response-header.",
    recommendation="Add a restrictive Permissions-Policy header for browser features.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers",),
    order=437,
)
def find_missing_permissions_policy(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _missing_header(
        config_ast,
        "Permissions-Policy",
        find_missing_permissions_policy,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.permissions_policy_unsafe",
    title="Permissions-Policy header is weak",
    severity="low",
    description="Lighttpd sets Permissions-Policy to a weak or unrecognized value.",
    recommendation="Use structured allowlists and avoid wildcard grants in Permissions-Policy.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers",),
    order=438,
)
def find_permissions_policy_unsafe(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _unsafe_header(
        config_ast,
        "Permissions-Policy",
        permissions_policy_is_safe,
        find_permissions_policy_unsafe,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


def _missing_header(
    config_ast: LighttpdConfigAst,
    header_name: str,
    rule_fn: Callable[..., list[Finding]],
    *,
    effective_config: LighttpdEffectiveConfig | None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None,
    request_context: LighttpdRequestContext | None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    if _has_header(
        config_ast,
        header_name,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    ):
        return []
    return [finding_from_rule(rule_fn, location=default_location(config_ast))]


def _has_header(
    config_ast: LighttpdConfigAst,
    header_name: str,
    *,
    effective_config: LighttpdEffectiveConfig | None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None,
    request_context: LighttpdRequestContext | None,
) -> bool:
    if merged_directives is not None and request_context is not None:
        return any(
            iter_header_values(
                config_ast,
                header_name=header_name,
                merged_directives=merged_directives,
                request_context=request_context,
            )
        )

    if effective_config is not None:
        return any(
            iter_header_values(
                config_ast,
                header_name=header_name,
                effective_config=LighttpdEffectiveConfig(
                    global_directives=effective_config.global_directives,
                    conditional_scopes=[],
                ),
            )
        )

    return any(iter_header_values(config_ast, header_name=header_name))


def _unsafe_header(
    config_ast: LighttpdConfigAst,
    header_name: str,
    is_safe: Callable[[str | None], bool],
    rule_fn: Callable[..., list[Finding]],
    *,
    effective_config: LighttpdEffectiveConfig | None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None,
    request_context: LighttpdRequestContext | None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    findings: list[Finding] = []
    for header in iter_header_values(
        config_ast,
        header_name=header_name,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    ):
        if is_safe(header.value):
            continue
        findings.append(
            finding_from_rule(
                rule_fn,
                location=_header_location(config_ast, header.source),
                metadata={"configured_value": header.value},
            )
        )
    return findings


def _header_location(
    config_ast: LighttpdConfigAst,
    source: LighttpdSourceSpan,
) -> SourceLocation:
    if source.file_path is not None and source.line is not None:
        return SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        )
    return default_location(config_ast)


__all__ = [
    "find_missing_content_security_policy",
    "find_missing_permissions_policy",
    "find_missing_referrer_policy",
    "find_missing_x_frame_options",
    "find_permissions_policy_unsafe",
    "find_referrer_policy_unsafe",
]
