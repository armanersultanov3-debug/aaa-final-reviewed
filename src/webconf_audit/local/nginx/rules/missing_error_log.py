"""nginx.missing_error_log -- Missing error_log directive."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    AstNode,
    find_child_directives,
)
from webconf_audit.local.nginx.rules._scope_utils import fragment_only_context_metadata
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_error_log"


@rule(
    rule_id=RULE_ID,
    title="Missing error_log directive",
    severity="low",
    description="Server block does not define an 'error_log' directive.",
    recommendation="Add an 'error_log' directive to this server block.",
    category="local",
    server_type="nginx",
    order=215,
)
def find_missing_error_log(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    context_metadata = fragment_only_context_metadata(config_ast)

    for server_block, inherited_directives in _iter_server_blocks_with_error_log(
        config_ast,
    ):
        finding = _find_missing_error_log_in_server(
            server_block,
            inherited_directives,
            context_metadata,
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _find_missing_error_log_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
    context_metadata: dict[str, str],
) -> Finding | None:
    error_log_directives = effective_child_directives(
        server_block,
        "error_log",
        inherited_directives,
    )

    if error_log_directives:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing error_log directive",
        severity="low",
        description="Server block does not define an 'error_log' directive.",
        recommendation="Add an 'error_log' directive to this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
        metadata=dict(context_metadata),
    )


def _iter_server_blocks_with_error_log(
    config_ast: ConfigAst,
) -> list[tuple[BlockNode, dict[str, list[DirectiveNode]]]]:
    servers: list[tuple[BlockNode, dict[str, list[DirectiveNode]]]] = []
    root_error_logs = [
        node
        for node in config_ast.nodes
        if isinstance(node, DirectiveNode) and node.name == "error_log"
    ]

    def walk(nodes: list[AstNode], inherited_error_logs: list[DirectiveNode]) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue
            current_error_logs = inherited_error_logs
            if node.name == "http":
                http_error_logs = find_child_directives(node, "error_log")
                if http_error_logs:
                    current_error_logs = http_error_logs
            if node.name == "server":
                servers.append((node, {"error_log": current_error_logs}))
                continue
            walk(node.children, current_error_logs)

    walk(config_ast.nodes, root_error_logs)
    return servers


__all__ = ["find_missing_error_log"]
