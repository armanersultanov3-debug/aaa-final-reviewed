"""lighttpd.content_security_policy_unsafe -- Content-Security-Policy is weak."""

from __future__ import annotations

from webconf_audit.csp import content_security_policy_directives
from webconf_audit.finding_factory import finding_from_rule
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

RULE_ID = "lighttpd.content_security_policy_unsafe"
_UNSAFE_SCRIPT_TOKENS = {"'unsafe-inline'", "'unsafe-eval'", "unsafe-inline", "unsafe-eval"}


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy is weak",
    severity="low",
    description="Lighttpd sets Content-Security-Policy without baseline protections.",
    recommendation=(
        "Include at least a restrictive default-src directive and avoid "
        "'unsafe-inline' / 'unsafe-eval' in script-src."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers",),
    standards=(
        cwe(693),
        owasp_top10_2021("A05:2021"),
        asvs_5(
            "3.4.3",
            coverage="partial",
            note="Baseline directives and unsafe script tokens only.",
        ),
    ),
    order=422,
)
def find_content_security_policy_unsafe(
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
        if _policy_is_baseline_safe(header.value):
            continue
        findings.append(_finding(config_ast, header.value, header.source))
    return findings


def _policy_is_baseline_safe(policy: str) -> bool:
    directives = content_security_policy_directives(policy.lower())
    if "default-src" not in directives:
        return False
    script_src = directives.get("script-src")
    if script_src is None:
        return True
    return not any(token in script_src.split() for token in _UNSAFE_SCRIPT_TOKENS)


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
        find_content_security_policy_unsafe,
        location=location,
        description=(
            "Lighttpd sets Content-Security-Policy without a restrictive "
            f"default-src or safe script-src posture: {value!r}."
        ),
    )


__all__ = ["find_content_security_policy_unsafe"]
