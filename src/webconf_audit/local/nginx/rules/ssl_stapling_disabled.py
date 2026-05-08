from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    AstNode,
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule
from webconf_audit.standards import asvs_5, owasp_top10_2021

RULE_ID = "nginx.ssl_stapling_disabled"


@rule(
    rule_id=RULE_ID,
    title="OCSP stapling is not enabled",
    severity="low",
    description="TLS server block does not enable 'ssl_stapling on'.",
    recommendation="Add 'ssl_stapling on;' to this server block.",
    category="local",
    server_type="nginx",
    standards=(
        owasp_top10_2021("A05:2021"),
        asvs_5(
            "12.1.4",
            coverage="partial",
            note="Local OCSP stapling enablement only.",
        ),
        StandardReference(
            standard="CIS",
            reference="NGINX v3.0.0 §4.1.7",
            url="https://www.cisecurity.org/benchmark/nginx",
            coverage="partial",
            note="Detects missing or off ssl_stapling in TLS server blocks.",
        ),
    ),
    order=248,
    tags=("tls",),
)
def find_ssl_stapling_disabled(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in _iter_server_blocks_with_http_stapling(config_ast):
        finding = _find_ssl_stapling_disabled_in_server(
            server_block,
            inherited_directives,
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _find_ssl_stapling_disabled_in_server(
    server_block: BlockNode,
    inherited_directives: list[DirectiveNode],
) -> Finding | None:
    if not server_uses_tls(server_block):
        return None

    ssl_stapling_directives = find_child_directives(server_block, "ssl_stapling")
    if _effective_ssl_stapling_is_on(ssl_stapling_directives, inherited_directives):
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


def _iter_server_blocks_with_http_stapling(
    config_ast: ConfigAst,
) -> list[tuple[BlockNode, list[DirectiveNode]]]:
    servers: list[tuple[BlockNode, list[DirectiveNode]]] = []

    def walk(nodes: list[AstNode], inherited_directives: list[DirectiveNode]) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue

            current_directives = inherited_directives
            if node.name == "http":
                current_directives = find_child_directives(node, "ssl_stapling")

            if node.name == "server":
                servers.append((node, current_directives))
                continue

            walk(node.children, current_directives)

    walk(config_ast.nodes, [])
    return servers


def _effective_ssl_stapling_is_on(
    server_directives: list[DirectiveNode],
    inherited_directives: list[DirectiveNode],
) -> bool:
    if server_directives:
        return _last_directive_is_on(server_directives)
    return _last_directive_is_on(inherited_directives)


def _last_directive_is_on(directives: list[DirectiveNode]) -> bool:
    if not directives:
        return False
    last = directives[-1]
    return len(last.args) == 1 and last.args[0].lower() == "on"


__all__ = ["find_ssl_stapling_disabled"]
