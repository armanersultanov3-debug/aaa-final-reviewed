"""lighttpd.content_security_policy_missing_frame_ancestors -- Content-Security-Policy missing frame-ancestors."""

from __future__ import annotations

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.header_policy import content_security_policy_has_frame_ancestors
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst, LighttpdSourceSpan
from webconf_audit.local.lighttpd.rules.header_tuple_utils import iter_header_values
from webconf_audit.local.lighttpd.rules.redirect_scope_utils import is_redirect_only_config
from webconf_audit.local.lighttpd.rules.rule_utils import default_location
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "lighttpd.content_security_policy_missing_frame_ancestors"


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy missing frame-ancestors",
    severity="low",
    description="Lighttpd sets Content-Security-Policy without frame-ancestors.",
    recommendation=(
        "Add a restrictive frame-ancestors directive such as 'none' or "
        "'self' to Content-Security-Policy."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers",),
    standards=(
        cwe(1021),
        owasp_top10_2021("A05:2021"),
        asvs_5("3.4.6"),
    ),
    order=423,
)
def find_content_security_policy_missing_frame_ancestors(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    findings: list[Finding] = []
    for header in iter_header_values(
        config_ast,
        header_name="Content-Security-Policy",
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    ):
        if content_security_policy_has_frame_ancestors(header.value):
            continue
        findings.append(_finding(config_ast, header.value, header.source))
    return findings


def _finding(
    config_ast: LighttpdConfigAst,
    value: str,
    source: LighttpdSourceSpan,
) -> Finding:
    location = (
        SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        )
        if source.file_path is not None and source.line is not None
        else default_location(config_ast)
    )
    return finding_from_rule(
        find_content_security_policy_missing_frame_ancestors,
        location=location,
        description=(
            "Lighttpd sets Content-Security-Policy without a frame-ancestors "
            f"directive: {value!r}."
        ),
    )


__all__ = ["find_content_security_policy_missing_frame_ancestors"]
