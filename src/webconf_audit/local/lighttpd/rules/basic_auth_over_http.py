"""lighttpd.basic_auth_over_http -- Basic authentication is enabled without SSL."""

from __future__ import annotations

import re

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdConditionalScope,
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdAstNode,
    LighttpdBlockNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    effective_directive_for_scope,
    normalize_value,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "lighttpd.basic_auth_over_http"
_BASIC_AUTH_RE = re.compile(
    r"""["']method["']\s*=>\s*["']basic["']""",
    re.IGNORECASE,
)


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
    standards=(
        cwe(319),
        owasp_top10_2021("A02:2021"),
        asvs_5("12.2.1"),
    ),
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
    auth = effective_directive_for_scope(effective_config, scope, "auth.require")
    if auth is None or not _uses_basic_auth(auth.value):
        return None
    ssl_engine = effective_directive_for_scope(effective_config, scope, "ssl.engine")
    if _ssl_enabled(ssl_engine):
        return None
    if "auth.require" not in scope.directives and "ssl.engine" not in scope.directives:
        return None
    return _finding(config_ast, auth.source.file_path, auth.source.line)


def _findings_from_ast(config_ast: LighttpdConfigAst) -> list[Finding]:
    return _findings_from_ast_nodes(
        config_ast,
        config_ast.nodes,
        inherited_ssl_enabled=False,
    )


def _findings_from_ast_nodes(
    config_ast: LighttpdConfigAst,
    nodes: list[LighttpdAstNode],
    *,
    inherited_ssl_enabled: bool,
) -> list[Finding]:
    ssl_enabled = _scope_ssl_enabled(nodes, inherited_ssl_enabled)
    findings: list[Finding] = []
    for node in nodes:
        if isinstance(node, LighttpdAssignmentNode):
            if (
                node.name == "auth.require"
                and _uses_basic_auth(node.value)
                and not ssl_enabled
            ):
                findings.append(
                    _finding(config_ast, node.source.file_path, node.source.line)
                )
            continue
        if isinstance(node, LighttpdBlockNode):
            findings.extend(
                _findings_from_ast_nodes(
                    config_ast,
                    node.children,
                    inherited_ssl_enabled=ssl_enabled,
                )
            )
    return findings


def _scope_ssl_enabled(
    nodes: list[LighttpdAstNode],
    inherited_ssl_enabled: bool,
) -> bool:
    ssl_enabled = inherited_ssl_enabled
    for node in nodes:
        if isinstance(node, LighttpdAssignmentNode) and node.name == "ssl.engine":
            ssl_enabled = normalize_value(node.value) == "enable"
    return ssl_enabled


def _uses_basic_auth(value: str) -> bool:
    return _BASIC_AUTH_RE.search(value) is not None


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
