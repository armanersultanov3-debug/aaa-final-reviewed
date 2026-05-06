from __future__ import annotations

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.header_policy import x_frame_options_is_safe
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
from webconf_audit.standards import cwe, owasp_top10_2021

RULE_ID = "lighttpd.x_frame_options_unsafe"


@rule(
    rule_id=RULE_ID,
    title="X-Frame-Options header is weak",
    severity="low",
    description="Lighttpd sets X-Frame-Options to an unsafe or unrecognized value.",
    recommendation='Set X-Frame-Options to "DENY" or "SAMEORIGIN".',
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers",),
    standards=(
        cwe(1021),
        owasp_top10_2021("A05:2021"),
    ),
    order=423,
)
def find_x_frame_options_unsafe(
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
        header_name="X-Frame-Options",
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    ):
        if x_frame_options_is_safe(header.value):
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
        find_x_frame_options_unsafe,
        location=location,
        description=(
            "Lighttpd sets X-Frame-Options to an unsafe or unrecognized value: "
            f"{value!r}."
        ),
    )


__all__ = ["find_x_frame_options_unsafe"]
