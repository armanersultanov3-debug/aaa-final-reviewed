from __future__ import annotations

from webconf_audit.csp import content_security_policy_has_reporting_endpoint
from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.redirect_scope_utils import is_redirect_only_config
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    iter_all_nodes,
    unquote,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "lighttpd.content_security_policy_missing_reporting_endpoint"

_HEADER_NAME = "content-security-policy"


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy missing reporting endpoint",
    severity="low",
    description="Content-Security-Policy is configured without report-uri or report-to.",
    recommendation=(
        "Add a CSP report-to or report-uri directive pointing at a controlled "
        "reporting endpoint."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers",),
    standards=(
        cwe(693),
        owasp_top10_2021("A05:2021"),
        asvs_5("3.4.7", coverage="partial", note="CSP reporting endpoint configured."),
    ),
    order=407,
)
def find_content_security_policy_missing_reporting_endpoint(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    if merged_directives is not None and request_context is not None:
        return (
            [_make_finding(config_ast)]
            if _has_csp_without_reporting_endpoint(merged_directives)
            else []
        )

    if effective_config is not None:
        return (
            [_make_finding(config_ast)]
            if _has_csp_without_reporting_endpoint(effective_config.global_directives)
            else []
        )

    return _find_from_ast(config_ast)


def _has_csp_without_reporting_endpoint(
    directives: dict[str, LighttpdEffectiveDirective],
) -> bool:
    directive = directives.get("setenv.add-response-header")
    if directive is None:
        return False
    values = _csp_values_from_tuple(unquote(directive.value))
    return any(
        not content_security_policy_has_reporting_endpoint(value)
        for value in values
    )


def _find_from_ast(config_ast: LighttpdConfigAst) -> list[Finding]:
    values: list[str] = []
    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != "setenv.add-response-header":
            continue
        values.extend(_csp_values_from_tuple(unquote(node.value)))
    if any(
        not content_security_policy_has_reporting_endpoint(value)
        for value in values
    ):
        return [_make_finding(config_ast)]
    return []


def _csp_values_from_tuple(raw: str) -> list[str]:
    stripped = raw.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]

    values: list[str] = []
    for pair in _split_tuple_items(stripped):
        if "=>" not in pair:
            continue
        key, _, value = pair.partition("=>")
        name = key.strip().strip('"').strip("'").lower()
        if name != _HEADER_NAME:
            continue
        values.append(value.strip().strip('"').strip("'"))
    return values


def _split_tuple_items(raw: str) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False

    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            current.append(char)
            quote = char
            continue
        if char == ",":
            items.append("".join(current))
            current = []
            continue
        current.append(char)

    if current or raw.endswith(","):
        items.append("".join(current))
    return items


def _make_finding(config_ast: LighttpdConfigAst) -> Finding:
    return finding_from_rule(
        find_content_security_policy_missing_reporting_endpoint,
        location=default_location(config_ast),
    )


__all__ = ["find_content_security_policy_missing_reporting_endpoint"]
