"""Implements rule ``nginx.proxy_pass_user_controlled_destination``.

Location: ``src/webconf_audit/local/nginx/rules/proxy_pass_user_controlled_destination.py``.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.local.nginx.rules._variable_taint_utils import TaintAnalyzer, extract_variables
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "nginx.proxy_pass_user_controlled_destination"
TITLE = "proxy_pass destination uses user-controlled host input"
DESCRIPTION = (
    "An Nginx proxy_pass directive interpolates user-controlled variables into "
    "the scheme/host portion of the upstream URL. This can redirect backend "
    "traffic to attacker-influenced destinations."
)
RECOMMENDATION = (
    "Keep proxy_pass upstream destinations fixed or map user input to an "
    "allowlisted set of upstream names without interpolating request-derived "
    "host components."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="high",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("proxy", "ssrf"),
    standards=(
        cwe(918),
        owasp_top10_2021("A10:2021"),
        asvs_5("1.3.6"),
    ),
    order=274,
)
def find_proxy_pass_user_controlled_destination(
    config_ast: ConfigAst,
) -> list[Finding]:
    analyzer = TaintAnalyzer(config_ast)
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, DirectiveNode) or node.name != "proxy_pass" or not node.args:
            continue
        host_expression = _proxy_pass_host_expression(node.args[0])
        if host_expression is None:
            continue
        scope = analyzer.scope_for_node(node)
        if not any(
            analyzer.is_user_controlled(
                variable_name,
                scope,
                in_proxy_pass_host=True,
            )
            for variable_name in extract_variables(host_expression)
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
                metadata={"proxy_pass": node.args[0]},
            )
        )

    return findings


def _proxy_pass_host_expression(value: str) -> str | None:
    scheme_separator = value.find("://")
    if scheme_separator == -1:
        # Variable-only form is valid in nginx and may carry a full upstream URL.
        return value if "$" in value else None
    remainder = value[scheme_separator + 3 :]
    if not remainder or remainder.startswith("unix:"):
        return None
    host_end = remainder.find("/")
    return remainder if host_end == -1 else remainder[:host_end]


__all__ = ["find_proxy_pass_user_controlled_destination"]
