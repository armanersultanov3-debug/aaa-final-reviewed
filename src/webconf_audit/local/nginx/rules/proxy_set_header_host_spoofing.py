from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.local.nginx.rules._variable_taint_utils import TaintAnalyzer
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "nginx.proxy_set_header_host_spoofing"
TITLE = "proxy_set_header forwards untrusted Host value"
DESCRIPTION = (
    "An Nginx proxy_set_header Host directive forwards request-controlled "
    "input to the upstream application. Applications that trust that Host "
    "value can generate attacker-controlled links, cache keys, redirects, or "
    "tenant routing decisions."
)
RECOMMENDATION = (
    "Use a fixed upstream Host value or Nginx's normalized $host value, and "
    "keep server_name matching strict for proxied virtual hosts."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("host", "proxy", "routing"),
    standards=(
        cwe(346),
        owasp_top10_2021("A05:2021"),
        asvs_5(
            "13.4.5",
            coverage="partial",
            note="Static detection of raw Host forwarding to upstream services.",
        ),
    ),
    order=276,
)
def find_proxy_set_header_host_spoofing(config_ast: ConfigAst) -> list[Finding]:
    analyzer = TaintAnalyzer(config_ast)
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not _is_host_proxy_set_header(node):
            continue
        header_value = " ".join(node.args[1:])
        if not analyzer.value_contains_user_controlled(
            header_value,
            analyzer.scope_for_node(node),
        ):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="medium",
                description=DESCRIPTION,
                recommendation=RECOMMENDATION,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
                metadata={"header_name": node.args[0], "header_value": header_value},
            )
        )

    return findings


def _is_host_proxy_set_header(node: object) -> bool:
    return (
        isinstance(node, DirectiveNode)
        and node.name == "proxy_set_header"
        and len(node.args) >= 2
        and node.args[0].lower() == "host"
    )


__all__ = ["find_proxy_set_header_host_spoofing"]
