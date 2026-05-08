from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules._default_server_rejection_utils import (
    rejects_unknown_hosts,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import listen_is_default_server
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.default_server_not_rejecting_unknown_hosts"


@rule(
    rule_id=RULE_ID,
    title="Default server does not reject unknown hosts",
    severity="low",
    description="A default_server block is present but does not explicitly reject unknown host names.",
    recommendation="Add 'return 444;' for HTTP catch-all blocks or 'ssl_reject_handshake on;' for TLS.",
    category="local",
    server_type="nginx",
    order=255,
)
def find_default_server_not_rejecting_unknown_hosts(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "server":
            continue
        if not _is_default_server(node) or rejects_unknown_hosts(node):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Default server does not reject unknown hosts",
                severity="low",
                description=(
                    "Server block is marked default_server, but it does not explicitly "
                    "reject requests for unknown host names."
                ),
                recommendation=(
                    "Use 'return 444;' for HTTP catch-all blocks or "
                    "'ssl_reject_handshake on;' for TLS catch-all blocks."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
            )
        )

    return findings


def _is_default_server(server_block: BlockNode) -> bool:
    return any(
        listen_is_default_server(directive)
        for directive in find_child_directives(server_block, "listen")
    )


__all__ = ["find_default_server_not_rejecting_unknown_hosts"]
