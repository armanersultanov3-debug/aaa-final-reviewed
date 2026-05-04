from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
)
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
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

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"error_log"},
    ):
        finding = _find_missing_error_log_in_server(server_block, inherited_directives)
        if finding is not None:
            findings.append(finding)

    return findings


def _find_missing_error_log_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
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
    )


__all__ = ["find_missing_error_log"]
