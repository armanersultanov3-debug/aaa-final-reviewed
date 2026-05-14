from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.local.nginx.rules._variable_taint_utils import TaintAnalyzer
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "nginx.crlf_in_add_header"
TITLE = "add_header value interpolates user-controlled input"
DESCRIPTION = (
    "An Nginx add_header directive builds a response header value from "
    "user-controlled variables. This can enable CRLF/header injection or unsafe "
    "header construction."
)
RECOMMENDATION = (
    "Avoid interpolating request-derived variables into add_header values unless "
    "they are strictly validated for the header context."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="high",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("headers", "injection"),
    standards=(
        cwe(113),
        owasp_top10_2021("A03:2021"),
        asvs_5(
            "1.1.2",
            coverage="partial",
            note="Header generation must keep untrusted values context-safe.",
        ),
    ),
    order=273,
)
def find_crlf_in_add_header(config_ast: ConfigAst) -> list[Finding]:
    analyzer = TaintAnalyzer(config_ast)
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, DirectiveNode) or node.name != "add_header":
            continue
        header_value = _header_value(node)
        if header_value is None:
            continue
        if not analyzer.value_contains_user_controlled(
            header_value,
            analyzer.scope_for_node(node),
        ):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="high",
                description=DESCRIPTION,
                recommendation=RECOMMENDATION,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
                metadata={"header_name": node.args[0]},
            )
        )

    return findings


def _header_value(directive: DirectiveNode) -> str | None:
    if len(directive.args) < 2:
        return None
    if directive.args[-1].lower() == "always" and len(directive.args) >= 3:
        return " ".join(directive.args[1:-1])
    return " ".join(directive.args[1:])


__all__ = ["find_crlf_in_add_header"]
