"""nginx.content_security_policy_missing_frame_ancestors -- Content-Security-Policy missing frame-ancestors."""

from __future__ import annotations

from webconf_audit.header_policy import content_security_policy_has_frame_ancestors
from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._scope_utils import skips_content_response_checks
from webconf_audit.local.nginx.rules._value_utils import iter_server_blocks_with_http_directives
from webconf_audit.local.nginx.rules.header_utils import find_server_add_headers
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "nginx.content_security_policy_missing_frame_ancestors"


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy missing frame-ancestors",
    severity="low",
    description="Content-Security-Policy is configured without frame-ancestors.",
    recommendation=(
        "Add a restrictive frame-ancestors directive such as 'none' or "
        "'self' to Content-Security-Policy."
    ),
    category="local",
    server_type="nginx",
    tags=("headers",),
    standards=(
        cwe(1021),
        owasp_top10_2021("A05:2021"),
        asvs_5("3.4.6"),
    ),
    order=255,
)
def find_content_security_policy_missing_frame_ancestors(
    config_ast: ConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header"},
    ):
        if skips_content_response_checks(server_block):
            continue
        csp_directives = [
            directive
            for directive in find_server_add_headers(server_block, inherited_directives)
            if directive.args and directive.args[0].lower() == "content-security-policy"
        ]
        if not csp_directives:
            continue
        if any(
            content_security_policy_has_frame_ancestors(_header_value(directive.args))
            for directive in csp_directives
        ):
            continue
        directive = csp_directives[0]
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Content-Security-Policy missing frame-ancestors",
                severity="low",
                description=(
                    "Content-Security-Policy is configured without a "
                    "frame-ancestors directive, so clickjacking restrictions "
                    "still depend on legacy X-Frame-Options behavior."
                ),
                recommendation=(
                    "Add a restrictive frame-ancestors directive such as "
                    "'none' or 'self' to Content-Security-Policy."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


def _header_value(args: list[str]) -> str:
    value_args = args[1:]
    if value_args and value_args[-1].lower() == "always":
        value_args = value_args[:-1]
    value = " ".join(value_args).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


__all__ = ["find_content_security_policy_missing_frame_ancestors"]
