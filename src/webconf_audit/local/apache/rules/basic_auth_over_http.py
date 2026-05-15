"""Implements rule ``apache.basic_auth_over_http``.

Location: ``src/webconf_audit/local/apache/rules/basic_auth_over_http.py``.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "apache.basic_auth_over_http"
TITLE = "Basic authentication is enabled on plain HTTP"
DESCRIPTION = (
    "Apache enables AuthType Basic outside a TLS VirtualHost. Basic "
    "authentication depends on TLS to protect reusable credentials."
)
RECOMMENDATION = (
    "Place Basic-auth protected scopes inside HTTPS VirtualHosts or otherwise "
    "require TLS before credentials are exchanged."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    tags=("auth", "tls"),
    standards=(
        cwe(319),
        owasp_top10_2021("A02:2021"),
        asvs_5("12.2.1"),
    ),
    order=367,
)
def find_basic_auth_over_http(config_ast: ApacheConfigAst) -> list[Finding]:
    return _findings(config_ast.nodes, tls_scope=False)


def _findings(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    tls_scope: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if not tls_scope and _is_basic_auth(node):
                findings.append(_finding(node))
            continue

        findings.extend(
            _findings(
                node.children,
                tls_scope=tls_scope or _block_is_tls_virtualhost(node),
            )
        )
    return findings


def _is_basic_auth(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "authtype"
        and bool(directive.args)
        and directive.args[0].lower() == "basic"
    )


def _block_is_tls_virtualhost(block: ApacheBlockNode) -> bool:
    if block.name.lower() != "virtualhost":
        return False
    if any(_address_mentions_tls(arg) for arg in block.args):
        return True
    return any(
        isinstance(child, ApacheDirectiveNode)
        and child.name.lower() == "sslengine"
        and child.args
        and child.args[0].lower() == "on"
        for child in block.children
    )


def _address_mentions_tls(value: str) -> bool:
    return value == "443" or value.endswith(":443")


def _finding(directive: ApacheDirectiveNode) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="medium",
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.source.file_path,
            line=directive.source.line,
        ),
    )


__all__ = ["find_basic_auth_over_http"]
