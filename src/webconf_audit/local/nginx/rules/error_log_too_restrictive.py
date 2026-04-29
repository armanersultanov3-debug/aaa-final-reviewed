from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.error_log_too_restrictive"

_TOO_RESTRICTIVE_LEVELS = {"error", "crit", "alert", "emerg"}


@rule(
    rule_id=RULE_ID,
    title="error_log level is too restrictive",
    severity="low",
    description="error_log suppresses operational events needed for incident response.",
    recommendation="Use an error_log destination with at least notice or info verbosity.",
    category="local",
    server_type="nginx",
    order=256,
)
def find_error_log_too_restrictive(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, DirectiveNode) or node.name != "error_log":
            continue
        if not _is_too_restrictive(node):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="error_log level is too restrictive",
                severity="low",
                description=(
                    "error_log points to /dev/null or uses a severity that suppresses "
                    "too many operational events."
                ),
                recommendation="Log errors to a real file with notice or info verbosity.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
            )
        )

    return findings


def _is_too_restrictive(directive: DirectiveNode) -> bool:
    if not directive.args:
        return True
    if directive.args[0].lower() == "/dev/null":
        return True
    if len(directive.args) < 2:
        return False
    return directive.args[1].lower() in _TOO_RESTRICTIVE_LEVELS


__all__ = ["find_error_log_too_restrictive"]
