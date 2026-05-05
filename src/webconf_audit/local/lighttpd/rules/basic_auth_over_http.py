from __future__ import annotations

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdConditionalScope,
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    effective_directive_for_scope,
    iter_all_nodes,
    normalize_value,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.basic_auth_over_http"


@rule(
    rule_id=RULE_ID,
    title="Basic authentication is enabled without SSL",
    severity="medium",
    description=(
        "Lighttpd configures Basic authentication while SSL is not enabled for "
        "the analyzed scope."
    ),
    recommendation=(
        "Enable SSL for Basic-auth protected scopes or avoid reusable "
        "credentials over plain HTTP."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("auth", "tls"),
    order=416,
)
def find_basic_auth_over_http(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        return _findings_from_directives(merged_directives, config_ast)
    if effective_config is not None:
        findings = _findings_from_directives(
            effective_config.global_directives,
            config_ast,
        )
        for scope in effective_config.conditional_scopes:
            scoped = _finding_from_scope(effective_config, scope, config_ast)
            if scoped is not None:
                findings.append(scoped)
        return findings
    return _findings_from_ast(config_ast)


def _findings_from_directives(
    directives: dict[str, LighttpdEffectiveDirective],
    config_ast: LighttpdConfigAst,
) -> list[Finding]:
    auth = directives.get("auth.require")
    if auth is None or not _uses_basic_auth(auth.value):
        return []
    if _ssl_enabled(directives.get("ssl.engine")):
        return []
    return [_finding(config_ast, auth.source.file_path, auth.source.line)]


def _finding_from_scope(
    effective_config: LighttpdEffectiveConfig,
    scope: LighttpdConditionalScope,
    config_ast: LighttpdConfigAst,
) -> Finding | None:
    auth = scope.directives.get("auth.require")
    if auth is None or not _uses_basic_auth(auth.value):
        return None
    ssl_engine = effective_directive_for_scope(effective_config, scope, "ssl.engine")
    if _ssl_enabled(ssl_engine):
        return None
    return _finding(config_ast, auth.source.file_path, auth.source.line)


def _findings_from_ast(config_ast: LighttpdConfigAst) -> list[Finding]:
    ssl_enabled = False
    auth: LighttpdAssignmentNode | None = None
    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name == "ssl.engine":
            ssl_enabled = normalize_value(node.value) == "enable"
        elif node.name == "auth.require" and _uses_basic_auth(node.value):
            auth = node
    if auth is None or ssl_enabled:
        return []
    return [_finding(config_ast, auth.source.file_path, auth.source.line)]


def _uses_basic_auth(value: str) -> bool:
    lowered = value.lower()
    return '"method" => "basic"' in lowered or "'method' => 'basic'" in lowered


def _ssl_enabled(directive: LighttpdEffectiveDirective | None) -> bool:
    return directive is not None and normalize_value(directive.value) == "enable"


def _finding(
    config_ast: LighttpdConfigAst,
    file_path: str | None,
    line: int | None,
) -> Finding:
    location = (
        SourceLocation(mode="local", kind="file", file_path=file_path, line=line)
        if file_path is not None and line is not None
        else default_location(config_ast)
    )
    return finding_from_rule(find_basic_auth_over_http, location=location)


__all__ = ["find_basic_auth_over_http"]
