from __future__ import annotations

import re

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.log_format_missing_fields"
_NGINX_VARIABLE_RE = re.compile(r"\$(?:\{(?P<braced>[A-Za-z0-9_]+)\}|(?P<plain>[A-Za-z0-9_]+))")
_ACCESS_LOG_OPTION_PREFIXES = ("buffer=", "flush=", "if=")

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
    used_format_names = _used_log_format_names(config_ast)

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, DirectiveNode) or node.name != "log_format":
            continue
        if not node.args or node.args[0] not in used_format_names:
            continue
        format_text = " ".join(node.args[1:])
        parsed_vars = _extract_variables(format_text)
        missing_fields = [field for field in _REQUIRED_FIELDS if field not in parsed_vars]
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


def _used_log_format_names(config_ast: ConfigAst) -> set[str]:
    used_format_names: set[str] = set()
    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, DirectiveNode) or node.name != "access_log":
            continue
        if len(node.args) < 2 or node.args[0].lower() == "off":
            continue
        format_name = node.args[1]
        if _is_access_log_option(format_name):
            continue
        used_format_names.add(format_name)
    return used_format_names


def _is_access_log_option(arg: str) -> bool:
    lowered = arg.lower()
    return lowered == "gzip" or any(
        lowered.startswith(prefix) for prefix in _ACCESS_LOG_OPTION_PREFIXES
    )


def _extract_variables(format_text: str) -> set[str]:
    return {
        f"${match.group('braced') or match.group('plain')}"
        for match in _NGINX_VARIABLE_RE.finditer(format_text)
    }


__all__ = ["find_log_format_missing_fields"]
