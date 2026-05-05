from __future__ import annotations

from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.rule_utils import (
    collect_modules,
    default_location,
    find_assignment,
    unquote,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.access_log_format_missing_fields"

_REQUIRED_FIELD_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("client address", ("%h", "%a")),
    ("remote user", ("%u",)),
    ("timestamp", ("%t",)),
    ("request line", ("%r",)),
    ("status", ("%>s", "%s")),
    ("response size", ("%b",)),
    ("user-agent", ("%{user-agent}i", "%{user_agent}i")),
)


@rule(
    rule_id=RULE_ID,
    title="Access log format misses audit fields",
    severity="low",
    description="Lighttpd accesslog.format is present but misses recommended audit fields.",
    recommendation=(
        "Include client address, remote user, timestamp, request, status, "
        "response size, and user-agent fields in accesslog.format."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=421,
)
def find_access_log_format_missing_fields(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        return _find_from_directives(config_ast, merged_directives)

    if effective_config is not None:
        findings = _find_from_directives(config_ast, effective_config.global_directives)
        for scope in effective_config.conditional_scopes:
            if not _scope_overrides_access_log(scope.directives):
                continue
            findings.extend(
                _find_from_directives(
                    config_ast,
                    {**effective_config.global_directives, **scope.directives},
                )
            )
        return findings

    if "mod_accesslog" not in collect_modules(config_ast):
        return []
    if find_assignment(config_ast, "accesslog.filename") is None:
        return []

    format_assignment = find_assignment(config_ast, "accesslog.format")
    if format_assignment is None:
        return []

    missing_fields = _missing_fields(unquote(format_assignment.value))
    if not missing_fields:
        return []
    return [
        _make_finding(
            config_ast,
            missing_fields,
            SourceLocation(
                mode="local",
                kind="file",
                file_path=format_assignment.source.file_path,
                line=format_assignment.source.line,
            ),
        )
    ]


def _find_from_directives(
    config_ast: LighttpdConfigAst,
    directives: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    if not _modules_include(directives, "mod_accesslog"):
        return []
    if "accesslog.filename" not in directives:
        return []

    format_directive = directives.get("accesslog.format")
    if format_directive is None:
        return []

    missing_fields = _missing_fields(unquote(format_directive.value))
    if not missing_fields:
        return []
    return [
        _make_finding(
            config_ast,
            missing_fields,
            SourceLocation(
                mode="local",
                kind="file",
                file_path=format_directive.source.file_path,
                line=format_directive.source.line,
            ),
        )
    ]


def _scope_overrides_access_log(
    directives: dict[str, LighttpdEffectiveDirective],
) -> bool:
    return "accesslog.filename" in directives or "accesslog.format" in directives


def _modules_include(
    directives: dict[str, LighttpdEffectiveDirective],
    module_name: str,
) -> bool:
    directive = directives.get("server.modules")
    if directive is None:
        return False
    return module_name in _parse_module_list(directive.value)


def _parse_module_list(value: str) -> set[str]:
    stripped = value.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]
    return {
        part.strip().strip('"').strip("'").strip()
        for part in stripped.split(",")
        if part.strip().strip('"').strip("'").strip()
    }


def _missing_fields(format_text: str) -> list[str]:
    lowered = format_text.lower()
    return [
        label
        for label, markers in _REQUIRED_FIELD_GROUPS
        if not any(marker in lowered for marker in markers)
    ]


def _make_finding(
    config_ast: LighttpdConfigAst,
    missing_fields: list[str],
    location: SourceLocation | None,
) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Access log format misses audit fields",
        severity="low",
        description=(
            "Lighttpd accesslog.format misses recommended audit fields: "
            + ", ".join(missing_fields)
        ),
        recommendation="Add the missing fields to accesslog.format.",
        location=location or default_location(config_ast),
    )


__all__ = ["find_access_log_format_missing_fields"]
