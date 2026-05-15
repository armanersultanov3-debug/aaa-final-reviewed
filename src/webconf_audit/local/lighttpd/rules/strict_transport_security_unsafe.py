"""lighttpd.strict_transport_security_unsafe -- Strict-Transport-Security header is weak."""

from __future__ import annotations

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.hsts_policy import hsts_policy_reason
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
    LighttpdSourceSpan,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    iter_all_nodes,
    unquote,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "lighttpd.strict_transport_security_unsafe"
_HEADER_NAME = "strict-transport-security"


@rule(
    rule_id=RULE_ID,
    title="Strict-Transport-Security header is weak",
    severity="medium",
    description="Lighttpd sets Strict-Transport-Security to an invalid or weak value.",
    recommendation=(
        'Set Strict-Transport-Security to "max-age=31536000; includeSubDomains".'
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("headers", "tls"),
    standards=(
        cwe(319),
        owasp_top10_2021("A05:2021"),
        asvs_5(
            "3.4.1",
            coverage="partial",
            note="Local max-age and includeSubDomains policy validation.",
        ),
    ),
    order=418,
)
def find_strict_transport_security_unsafe(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        return _findings_from_directives(config_ast, merged_directives)
    if effective_config is not None:
        findings = _findings_from_directives(
            config_ast,
            effective_config.global_directives,
        )
        for scope in effective_config.conditional_scopes:
            findings.extend(_findings_from_directives(config_ast, scope.directives))
        return findings
    return _findings_from_ast(config_ast)


def _findings_from_directives(
    config_ast: LighttpdConfigAst,
    directives: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    directive = directives.get("setenv.add-response-header")
    if directive is None:
        return []
    value = _hsts_value_from_tuple(directive.value)
    if value is None:
        return []
    reason = hsts_policy_reason(value)
    if reason is None:
        return []
    return [_finding(config_ast, value, reason, directive.source)]


def _findings_from_ast(config_ast: LighttpdConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != "setenv.add-response-header":
            continue
        value = _hsts_value_from_tuple(node.value)
        if value is None:
            continue
        reason = hsts_policy_reason(value)
        if reason is None:
            continue
        findings.append(_finding(config_ast, value, reason, node.source))
    return findings


def _hsts_value_from_tuple(raw: str) -> str | None:
    stripped = raw.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]
    for pair in _split_tuple_items(stripped):
        key, separator, value = pair.partition("=>")
        if not separator:
            continue
        if unquote(key.strip()).lower() == _HEADER_NAME:
            return unquote(value.strip())
    return None


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


def _finding(
    config_ast: LighttpdConfigAst,
    value: str,
    reason: str,
    source: LighttpdSourceSpan,
) -> Finding:
    location = (
        SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        )
        if source.file_path is not None and source.line is not None
        else default_location(config_ast)
    )
    return finding_from_rule(
        find_strict_transport_security_unsafe,
        location=location,
        description=(
            f"Lighttpd sets Strict-Transport-Security to {value!r}: {reason}."
        ),
    )


__all__ = ["find_strict_transport_security_unsafe"]
