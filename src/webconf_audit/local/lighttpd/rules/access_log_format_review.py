"""lighttpd.access_log_format_review -- policy-review rule.

Surfaces the effective ``accesslog.format`` value (or notes "default
common-log format" when it is not configured) for an operator to
review against the organisation's SIEM / retention policy. The right
field set depends on the downstream log pipeline and cannot be judged
without knowing the deployment.

Opt-in: only runs when ``--enable-policy-review`` is set on the CLI.
"""

from __future__ import annotations

from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.rule_utils import (
    collect_modules,
    find_assignment,
    unquote,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.access_log_format_review"

_MAX_REPORTED_FORMAT_LEN = 200


@rule(
    rule_id=RULE_ID,
    title="accesslog.format value needs operator review",
    severity="info",
    description=(
        "Lighttpd accesslog is configured. The chosen format (or implicit "
        "default) determines which fields reach the SIEM and needs "
        "operator review against the logging policy."
    ),
    recommendation=(
        "Confirm the configured accesslog.format (or implicit default) "
        "matches your SIEM / retention requirements. Document the choice "
        "or extend the format if required fields are missing."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("policy-review", "logging"),
    order=480,
)
def find_access_log_format_review(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        return _from_directives(config_ast, merged_directives)

    if effective_config is not None:
        return _from_directives(config_ast, effective_config.global_directives)

    if "mod_accesslog" not in collect_modules(config_ast):
        return []
    filename_assignment = find_assignment(config_ast, "accesslog.filename")
    if filename_assignment is None:
        return []

    format_assignment = find_assignment(config_ast, "accesslog.format")
    if format_assignment is not None:
        value = unquote(format_assignment.value)
        return [_format_finding(value, format_assignment.source.file_path, format_assignment.source.line)]
    return [
        _default_format_finding(
            filename_assignment.source.file_path,
            filename_assignment.source.line,
        )
    ]


def _from_directives(
    config_ast: LighttpdConfigAst,
    directives: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    if not _modules_include(directives, "mod_accesslog"):
        return []
    if "accesslog.filename" not in directives:
        return []
    filename_directive = directives["accesslog.filename"]

    format_directive = directives.get("accesslog.format")
    if format_directive is not None:
        return [
            _format_finding(
                unquote(format_directive.value),
                format_directive.source.file_path,
                format_directive.source.line,
            )
        ]
    return [
        _default_format_finding(
            filename_directive.source.file_path,
            filename_directive.source.line,
        )
    ]


def _modules_include(
    directives: dict[str, LighttpdEffectiveDirective],
    module_name: str,
) -> bool:
    directive = directives.get("server.modules")
    if directive is None:
        return False
    value = directive.value.strip()
    if value.startswith("(") and value.endswith(")"):
        value = value[1:-1]
    parts = {
        part.strip().strip('"').strip("'").strip()
        for part in value.split(",")
        if part.strip().strip('"').strip("'").strip()
    }
    return module_name in parts


def _format_finding(value: str, file_path: str | None, line: int | None) -> Finding:
    displayed = (
        value[:_MAX_REPORTED_FORMAT_LEN] + "..."
        if len(value) > _MAX_REPORTED_FORMAT_LEN
        else value
    )
    return Finding(
        rule_id=RULE_ID,
        title="accesslog.format value needs operator review",
        severity="info",
        description=(
            f"Configured accesslog.format: {displayed}. Confirm this matches "
            "your SIEM / retention policy."
        ),
        recommendation=(
            "Document the configured format or extend it if required audit "
            "fields are missing."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=file_path,
            line=line,
        ),
    )


def _default_format_finding(file_path: str | None, line: int | None) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="accesslog.format uses Lighttpd's default common-log format",
        severity="info",
        description=(
            "accesslog.filename is set without an explicit accesslog.format, "
            "so Lighttpd's built-in common-log format is used. Decide "
            "whether this matches your SIEM / retention policy."
        ),
        recommendation=(
            "If your pipeline needs additional audit fields (user-agent, "
            "request-id, forwarded chain), define accesslog.format explicitly."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=file_path,
            line=line,
        ),
    )


__all__ = ["find_access_log_format_review"]
