from __future__ import annotations

from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    has_assignment,
)
from webconf_audit.local.lighttpd.rules.redirect_scope_utils import (
    is_redirect_only_config,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.max_request_size_missing"


@rule(
    rule_id=RULE_ID,
    title="Maximum request size not configured",
    severity="low",
    description="server.max-request-size is not set.",
    recommendation="Set server.max-request-size to limit the maximum allowed request body size.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=404,
)
def find_max_request_size_missing(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    if merged_directives is not None and request_context is not None:
        return [] if "server.max-request-size" in merged_directives else [_make_finding(config_ast)]

    if effective_config is not None:
        return (
            []
            if "server.max-request-size" in effective_config.global_directives
            else [_make_finding(config_ast)]
        )

    if has_assignment(config_ast, "server.max-request-size"):
        return []

    return [_make_finding(config_ast)]


def _make_finding(config_ast: LighttpdConfigAst) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Maximum request size not configured",
        severity="low",
        description="server.max-request-size is not set.",
        recommendation="Set server.max-request-size to limit the maximum allowed request body size.",
        location=default_location(config_ast),
    )


__all__ = ["find_max_request_size_missing"]
