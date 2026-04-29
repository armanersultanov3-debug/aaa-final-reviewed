from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.log_format_missing_fields"

_REQUIRED_FIELDS = (
    "$time_iso8601",
    "$remote_addr",
    "$remote_user",
    "$request",
    "$status",
    "$http_user_agent",
)


@rule(
    rule_id=RULE_ID,
    title="log_format misses detailed audit fields",
    severity="low",
    description="log_format is present but does not include the recommended audit fields.",
    recommendation=(
        "Include timestamp, client address, remote user, request, status, and "
        "user-agent fields in access log formats."
    ),
    category="local",
    server_type="nginx",
    order=257,
)
def find_log_format_missing_fields(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, DirectiveNode) or node.name != "log_format":
            continue
        format_text = " ".join(node.args[1:])
        missing_fields = [field for field in _REQUIRED_FIELDS if field not in format_text]
        if not missing_fields:
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="log_format misses detailed audit fields",
                severity="low",
                description=(
                    "log_format does not include required audit fields: "
                    + ", ".join(missing_fields)
                ),
                recommendation=(
                    "Add the missing fields to the log_format used by access_log."
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


__all__ = ["find_log_format_missing_fields"]
