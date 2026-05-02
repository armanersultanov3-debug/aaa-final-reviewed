from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import iter_directives
from webconf_audit.local.apache.rules._log_policy_utils import (
    defined_log_format_name,
    referenced_log_format_name,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_log_format"


@rule(
    rule_id=RULE_ID,
    title="CustomLog references undefined LogFormat",
    severity="low",
    description="Apache CustomLog uses a named format that is not defined.",
    recommendation="Define a matching LogFormat or use a known built-in format.",
    category="local",
    server_type="apache",
    order=347,
)
def find_missing_log_format(config_ast: ApacheConfigAst) -> list[Finding]:
    defined_formats = {
        format_name
        for directive in iter_directives(config_ast.nodes, "logformat")
        if (format_name := defined_log_format_name(directive)) is not None
    }

    for custom_log in iter_directives(config_ast.nodes, "customlog"):
        format_name = referenced_log_format_name(custom_log)
        if format_name is None or format_name in defined_formats:
            continue

        return [
            Finding(
                rule_id=RULE_ID,
                title="CustomLog references undefined LogFormat",
                severity="low",
                description=f"CustomLog references undefined LogFormat '{format_name}'.",
                recommendation="Define a matching LogFormat or use a known built-in format.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=custom_log.source.file_path,
                    line=custom_log.source.line,
                ),
            )
        ]

    return []


__all__ = ["find_missing_log_format"]
