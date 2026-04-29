from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.ssl_stapling_disabled"


@rule(
    rule_id=RULE_ID,
    title="OCSP stapling is not enabled",
    severity="low",
    description="TLS server block does not enable 'ssl_stapling on'.",
    recommendation="Add 'ssl_stapling on;' to this server block.",
    category="local",
    server_type="nginx",
    order=248,
)
def find_ssl_stapling_disabled(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_ssl_stapling_disabled_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_ssl_stapling_disabled_in_server(server_block: BlockNode) -> Finding | None:
    if not server_uses_tls(server_block):
        return None

    ssl_stapling_directives = find_child_directives(server_block, "ssl_stapling")
    if _last_directive_is_on(ssl_stapling_directives):
        return None

    return Finding(
        rule_id=RULE_ID,
        title="OCSP stapling is not enabled",
        severity="low",
        description="TLS server block does not enable 'ssl_stapling on'.",
        recommendation="Add 'ssl_stapling on;' to this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


def _last_directive_is_on(directives: list[DirectiveNode]) -> bool:
    if not directives:
        return False
    last = directives[-1]
    return len(last.args) == 1 and last.args[0].lower() == "on"


__all__ = ["find_ssl_stapling_disabled"]
