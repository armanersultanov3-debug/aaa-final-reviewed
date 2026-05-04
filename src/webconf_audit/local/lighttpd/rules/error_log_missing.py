from __future__ import annotations

from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    has_assignment,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.error_log_missing"


@rule(
    rule_id=RULE_ID,
    title="Error log not configured",
    severity="medium",
    description="server.errorlog is not configured.",
    recommendation="Set server.errorlog to a file path to capture error output.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=402,
)
def find_error_log_missing(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        return [] if "server.errorlog" in merged_directives else [_make_finding(config_ast)]

    if effective_config is not None:
        return (
            []
            if "server.errorlog" in effective_config.global_directives
            else [_make_finding(config_ast)]
        )

    if has_assignment(config_ast, "server.errorlog"):
        return []

    return [_make_finding(config_ast)]


def _make_finding(config_ast: LighttpdConfigAst) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Error log not configured",
        severity="medium",
        description="server.errorlog is not configured.",
        recommendation="Set server.errorlog to a file path to capture error output.",
        location=default_location(config_ast),
    )


__all__ = ["find_error_log_missing"]
