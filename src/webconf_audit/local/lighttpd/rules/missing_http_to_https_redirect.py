from __future__ import annotations

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.directive_value_utils import (
    configured_value,
)
from webconf_audit.local.lighttpd.rules.redirect_scope_utils import (
    is_redirect_only_config,
    redirect_value_targets_whole_https,
)
from webconf_audit.local.lighttpd.rules.rule_utils import default_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.missing_http_to_https_redirect"


@rule(
    rule_id=RULE_ID,
    title="HTTP host does not redirect to HTTPS",
    severity="low",
    description="A named Lighttpd HTTP host listens without an HTTPS redirect policy.",
    recommendation="Enable mod_redirect and add a url.redirect rule that sends HTTP clients to HTTPS.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("tls",),
    order=443,
)
def find_missing_http_to_https_redirect(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    if merged_directives is not None and request_context is not None:
        return _find_from_directives(config_ast, merged_directives)

    if effective_config is not None:
        return _find_from_directives(config_ast, effective_config.global_directives)

    return []


def _find_from_directives(
    config_ast: LighttpdConfigAst,
    directives: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    if not _is_named_http_host(directives):
        return []
    if _has_https_redirect(directives):
        return []
    return [finding_from_rule(find_missing_http_to_https_redirect, location=default_location(config_ast))]


def _is_named_http_host(
    directives: dict[str, LighttpdEffectiveDirective],
) -> bool:
    if "server.name" not in directives:
        return False
    port = directives.get("server.port")
    return port is None or configured_value(port) == "80"


def _has_https_redirect(
    directives: dict[str, LighttpdEffectiveDirective],
) -> bool:
    modules = directives.get("server.modules")
    if modules is None or "mod_redirect" not in _module_names(configured_value(modules)):
        return False

    redirect = directives.get("url.redirect")
    if redirect is None:
        return False
    return redirect_value_targets_whole_https(configured_value(redirect))


def _module_names(value: str) -> set[str]:
    stripped = value.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]
    return {
        part.strip().strip('"').strip("'").strip()
        for part in stripped.split(",")
        if part.strip().strip('"').strip("'").strip()
    }


__all__ = ["find_missing_http_to_https_redirect"]
