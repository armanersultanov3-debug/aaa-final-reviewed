from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.local.nginx.rules._variable_taint_utils import TaintAnalyzer
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "nginx.crlf_in_return"
TITLE = "Return directive interpolates user-controlled input"
DESCRIPTION = (
    "An Nginx return directive builds a response body or redirect target from "
    "user-controlled variables. This can enable CRLF/header injection or unsafe "
    "redirect response construction."
)
RECOMMENDATION = (
    "Do not interpolate request-derived variables into return text or redirect "
    "targets unless they are strictly validated for the target context."
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
            note="Response/header generation must keep untrusted values context-safe.",
        ),
    ),
    order=272,
)
def find_crlf_in_return(config_ast: ConfigAst) -> list[Finding]:
    analyzer = TaintAnalyzer(config_ast)
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, DirectiveNode) or node.name != "return":
            continue
        return_value = _return_value(node)
        if return_value is None:
            continue
        if not analyzer.value_contains_user_controlled(
            return_value,
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
            )
        )

    return findings


def _return_value(directive: DirectiveNode) -> str | None:
    if not directive.args:
        return None
    if len(directive.args) == 1:
        return directive.args[0]
    return " ".join(directive.args[1:]) if _looks_like_status_code(directive.args[0]) else " ".join(directive.args)


def _looks_like_status_code(value: str) -> bool:
    return len(value) == 3 and value.isdigit()


__all__ = ["find_crlf_in_return"]
