"""nginx.missing_log_format -- Missing log_format directive."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_log_format"
_ACCESS_LOG_OPTION_PREFIXES = ("buffer=", "flush=", "gzip=", "if=")
_BUILTIN_LOG_FORMATS = {"combined"}


@rule(
    rule_id=RULE_ID,
    title="Missing log_format directive",
    severity="low",
    description="Configuration uses a named access_log format but does not define it.",
    recommendation="Add a matching 'log_format' directive or use the default access log format.",
    category="local",
    server_type="nginx",
    order=225,
)
def find_missing_log_format(config_ast: ConfigAst) -> list[Finding]:
    defined_format_names = {
        node.args[0]
        for node in iter_nodes(config_ast.nodes)
        if isinstance(node, DirectiveNode) and node.name == "log_format" and node.args
    }

    access_log_format_references = [
        (node, format_name)
        for node in iter_nodes(config_ast.nodes)
        if isinstance(node, DirectiveNode)
        and node.name == "access_log"
        and (format_name := _referenced_log_format(node)) is not None
    ]

    if not access_log_format_references:
        return []

    first_missing_reference = next(
        (
            (node, format_name)
            for node, format_name in access_log_format_references
            if format_name not in defined_format_names
        ),
        None,
    )
    if first_missing_reference is None:
        return []

    first_access_log, format_name = first_missing_reference

    return [
        Finding(
            rule_id=RULE_ID,
            title="Missing log_format directive",
            severity="low",
            description=f"access_log references undefined log_format '{format_name}'.",
            recommendation="Add a matching 'log_format' directive or use the default access log format.",
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=first_access_log.source.file_path,
                line=first_access_log.source.line,
            ),
        )
    ]


def _referenced_log_format(directive: DirectiveNode) -> str | None:
    if len(directive.args) < 2 or directive.args[0].lower() == "off":
        return None
    format_name = directive.args[1]
    if format_name.lower() in _BUILTIN_LOG_FORMATS or _is_access_log_option(format_name):
        return None
    return format_name


def _is_access_log_option(arg: str) -> bool:
    lowered = arg.lower()
    return lowered == "gzip" or any(
        lowered.startswith(prefix) for prefix in _ACCESS_LOG_OPTION_PREFIXES
    )


__all__ = ["find_missing_log_format"]
