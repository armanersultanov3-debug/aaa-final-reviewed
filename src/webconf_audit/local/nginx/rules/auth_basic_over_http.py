from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules._scope_utils import skips_content_response_checks
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.auth_basic_over_http"
TITLE = "Basic authentication is enabled on plain HTTP"
DESCRIPTION = (
    "Nginx enables auth_basic on a non-TLS content-serving scope. Basic "
    "authentication depends on TLS to protect reusable credentials."
)
RECOMMENDATION = (
    "Serve Basic-auth protected scopes only over HTTPS, or redirect plain HTTP "
    "before authentication is applied."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("auth", "tls"),
    order=264,
)
def find_auth_basic_over_http(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "server":
            continue
        if server_uses_tls(node) or skips_content_response_checks(node):
            continue
        auth_directive = _first_active_auth_basic(node)
        if auth_directive is None:
            continue
        findings.append(_finding(auth_directive))
    return findings


def _first_active_auth_basic(server_block: BlockNode) -> DirectiveNode | None:
    server_auth = _active_auth_basic_directive(server_block)
    if server_auth is not None:
        return server_auth

    for child in server_block.children:
        if not isinstance(child, BlockNode):
            continue
        if child.name not in {"location", "limit_except"}:
            continue
        scoped_auth = _first_active_auth_basic_in_scope(child)
        if scoped_auth is not None:
            return scoped_auth
    return None


def _first_active_auth_basic_in_scope(block: BlockNode) -> DirectiveNode | None:
    auth = _active_auth_basic_directive(block)
    if auth is not None:
        return auth
    for child in block.children:
        if isinstance(child, BlockNode):
            nested = _first_active_auth_basic_in_scope(child)
            if nested is not None:
                return nested
    return None


def _active_auth_basic_directive(block: BlockNode) -> DirectiveNode | None:
    directives = find_child_directives(block, "auth_basic")
    if not directives:
        return None
    last = directives[-1]
    if not last.args or last.args[0].strip('"').strip("'").lower() == "off":
        return None
    return last


def _finding(directive: DirectiveNode) -> Finding:
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


__all__ = ["find_auth_basic_over_http"]
