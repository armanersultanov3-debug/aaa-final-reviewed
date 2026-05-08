from __future__ import annotations

from webconf_audit.hsts_policy import hsts_policy_reason
from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode
from webconf_audit.local.nginx.rules._value_utils import iter_server_blocks_with_http_directives
from webconf_audit.local.nginx.rules.header_utils import find_server_add_headers
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "nginx.hsts_header_unsafe"
TITLE = "Strict-Transport-Security header is weak"
DESCRIPTION = "Nginx sets Strict-Transport-Security to an invalid or weak value."
RECOMMENDATION = (
    'Set Strict-Transport-Security to "max-age=31536000; includeSubDomains" '
    "on TLS server blocks."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("headers", "tls"),
    standards=(
        cwe(319),
        owasp_top10_2021("A05:2021"),
        asvs_5(
            "3.4.1",
            coverage="partial",
            note="Local max-age and includeSubDomains policy validation.",
        ),
    ),
    order=265,
)
def find_hsts_header_unsafe(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header"},
    ):
        if not server_uses_tls(server_block):
            continue
        directive = _effective_hsts_header(server_block, inherited_directives)
        if directive is None or len(directive.args) < 2:
            continue
        reason = hsts_policy_reason(directive.args[1])
        if reason is None:
            continue
        findings.append(_finding(directive, directive.args[1], reason))
    return findings


def _effective_hsts_header(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> DirectiveNode | None:
    matches = [
        directive
        for directive in find_server_add_headers(server_block, inherited_directives)
        if directive.args and directive.args[0].lower() == "strict-transport-security"
    ]
    return matches[-1] if matches else None


def _finding(directive: DirectiveNode, value: str, reason: str) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="medium",
        description=(
            f"Nginx sets Strict-Transport-Security to {value!r}: {reason}."
        ),
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.source.file_path,
            line=directive.source.line,
        ),
    )


__all__ = ["find_hsts_header_unsafe"]
