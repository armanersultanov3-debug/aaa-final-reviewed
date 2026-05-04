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

RULE_ID = "nginx.missing_access_log"


@rule(
    rule_id=RULE_ID,
    title="Missing access_log directive",
    severity="low",
    description="Server block does not define an enabled 'access_log' directive.",
    recommendation="Add an enabled 'access_log' directive to this server block.",
    category="local",
    server_type="nginx",
    order=206,
)
def find_missing_access_log(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"access_log"},
    ):
        finding = _find_missing_access_log_in_server(server_block, inherited_directives)
        if finding is not None:
            findings.append(finding)

    return findings


def _find_missing_access_log_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> Finding | None:
    access_log_directives = effective_child_directives(
        server_block,
        "access_log",
        inherited_directives,
    )

    if any(_directive_disables_access_log(directive) for directive in access_log_directives):
        effective_access_log_enabled = False
    else:
        effective_access_log_enabled = any(
            _directive_enables_access_log(directive)
            for directive in access_log_directives
        )
    if effective_access_log_enabled:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing access_log directive",
        severity="low",
        description="Server block does not define an enabled 'access_log' directive.",
        recommendation="Add an enabled 'access_log' directive to this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


def _directive_enables_access_log(directive: DirectiveNode) -> bool:
    return bool(directive.args) and directive.args[0].lower() != "off"


def _directive_disables_access_log(directive: DirectiveNode) -> bool:
    return len(directive.args) == 1 and directive.args[0].lower() == "off"


__all__ = ["find_missing_access_log"]
