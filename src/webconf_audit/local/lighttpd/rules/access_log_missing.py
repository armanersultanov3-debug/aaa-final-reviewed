"""lighttpd.access_log_missing -- Access log file not configured."""

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
    has_assignment,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.access_log_missing"


@rule(
    rule_id=RULE_ID,
    title="Access log file not configured",
    severity="low",
    description="mod_accesslog is loaded but accesslog.filename is not set.",
    recommendation="Set accesslog.filename to a file path to capture access logs.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=400,
)
def find_access_log_missing(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        return _find_from_merged(config_ast, merged_directives)

    if effective_config is not None:
        return _find_from_effective(config_ast, effective_config)

    modules = collect_modules(config_ast)

    if "mod_accesslog" not in modules:
        return []

    if has_assignment(config_ast, "accesslog.filename"):
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Access log file not configured",
            severity="low",
            description=(
                "mod_accesslog is loaded but accesslog.filename is not set."
            ),
            recommendation="Set accesslog.filename to a file path to capture access logs.",
            location=default_location(config_ast),
        )
    ]


def _find_from_merged(
    config_ast: LighttpdConfigAst,
    merged_directives: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    if not _merged_modules_include(merged_directives, "mod_accesslog"):
        return []
    if "accesslog.filename" in merged_directives:
        return []
    return [_make_finding(config_ast)]


def _find_from_effective(
    config_ast: LighttpdConfigAst,
    effective_config: LighttpdEffectiveConfig,
) -> list[Finding]:
    if not _merged_modules_include(effective_config.global_directives, "mod_accesslog"):
        return []
    if "accesslog.filename" in effective_config.global_directives:
        return []
    return [_make_finding(config_ast)]


def _merged_modules_include(
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


def _make_finding(config_ast: LighttpdConfigAst) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Access log file not configured",
        severity="low",
        description="mod_accesslog is loaded but accesslog.filename is not set.",
        recommendation="Set accesslog.filename to a file path to capture access logs.",
        location=default_location(config_ast),
    )


__all__ = ["find_access_log_missing"]
