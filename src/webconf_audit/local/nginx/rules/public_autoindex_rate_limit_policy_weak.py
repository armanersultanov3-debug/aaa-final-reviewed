"""Implements rule ``nginx.public_autoindex_rate_limit_policy_weak``.

Location: ``src/webconf_audit/local/nginx/rules/public_autoindex_rate_limit_policy_weak.py``.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules._limit_utils import (
    find_zone_name,
    iter_directives,
    parse_positive_integer,
    parse_rate_per_second,
)
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
    last_directive_is_on,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.public_autoindex_rate_limit_policy_weak"
TITLE = "Public autoindex rate-limit policy is weak"
DESCRIPTION = (
    "Nginx serves a public autoindex scope where request or connection limits "
    "are not effective for that scope, or are set to very high values."
)
RECOMMENDATION = (
    "Apply per-client limit_req and limit_conn controls to the public autoindex "
    "scope, and use deployment-appropriate values."
)
_MAX_PUBLIC_AUTOINDEX_REQUEST_RATE_PER_SECOND = 120.0
_MAX_PUBLIC_AUTOINDEX_CONNECTIONS = 100


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    order=268,
)
def find_public_autoindex_rate_limit_policy_weak(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    zone_rates = _limit_req_zone_rates(config_ast)

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"autoindex", "limit_req", "limit_conn"},
    ):
        configured_limits = {
            "limit_req": _has_configured_limit(server_block, inherited_directives, "limit_req"),
            "limit_conn": _has_configured_limit(server_block, inherited_directives, "limit_conn"),
        }
        for scope, autoindex_directive in _public_autoindex_scopes(
            server_block,
            inherited_directives,
        ):
            weaknesses = _scope_weaknesses(
                scope,
                server_block,
                inherited_directives,
                configured_limits,
                zone_rates,
            )
            if weaknesses:
                findings.append(_finding(autoindex_directive, weaknesses))

    return findings


def _limit_req_zone_rates(config_ast: ConfigAst) -> dict[str, float]:
    rates: dict[str, float] = {}
    for directive in iter_directives(config_ast, "limit_req_zone"):
        zone_name = find_zone_name(directive.args)
        if zone_name is None:
            continue
        for arg in directive.args:
            if not arg.startswith("rate="):
                continue
            parsed = parse_rate_per_second(arg.removeprefix("rate="))
            if parsed is not None:
                rates[zone_name] = parsed
    return rates


def _public_autoindex_scopes(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> list[tuple[BlockNode, DirectiveNode]]:
    scopes: list[tuple[BlockNode, DirectiveNode]] = []
    server_autoindex = effective_child_directives(
        server_block,
        "autoindex",
        inherited_directives,
    )
    if last_directive_is_on(server_autoindex):
        scopes.append((server_block, server_autoindex[-1]))

    for node in iter_nodes(server_block.children):
        if not isinstance(node, BlockNode) or node.name != "location":
            continue
        if _location_is_internal_or_named(node):
            continue
        location_autoindex = find_child_directives(node, "autoindex")
        if last_directive_is_on(location_autoindex):
            scopes.append((node, location_autoindex[-1]))
    return scopes


def _scope_weaknesses(
    scope: BlockNode,
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
    configured_limits: dict[str, bool],
    zone_rates: dict[str, float],
) -> list[str]:
    weaknesses: list[str] = []
    limit_req = _effective_limit_directives(
        scope,
        server_block,
        inherited_directives,
        "limit_req",
    )
    limit_conn = _effective_limit_directives(
        scope,
        server_block,
        inherited_directives,
        "limit_conn",
    )
    limit_req_rates = _valid_limit_req_rates(limit_req, zone_rates)
    limit_conn_limits = _valid_limit_conn_limits(limit_conn)

    if configured_limits["limit_req"] and not limit_req_rates:
        weaknesses.append("limit_req_not_effective")
    elif _limit_req_values_too_high(limit_req_rates):
        weaknesses.append("limit_req_rate_too_high")

    if configured_limits["limit_conn"] and not limit_conn_limits:
        weaknesses.append("limit_conn_not_effective")
    elif _limit_conn_values_too_high(limit_conn_limits):
        weaknesses.append("limit_conn_limit_too_high")

    return weaknesses


def _effective_limit_directives(
    scope: BlockNode,
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
    directive_name: str,
) -> list[DirectiveNode]:
    if scope is not server_block:
        scope_directives = find_child_directives(scope, directive_name)
        if scope_directives:
            return scope_directives

    server_directives = find_child_directives(server_block, directive_name)
    if server_directives:
        return server_directives
    return inherited_directives.get(directive_name, [])


def _has_configured_limit(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
    directive_name: str,
) -> bool:
    if inherited_directives.get(directive_name):
        return True
    return any(
        isinstance(node, DirectiveNode) and node.name == directive_name
        for node in iter_nodes(server_block.children)
    )


def _limit_req_values_too_high(
    rates: list[float],
) -> bool:
    return bool(rates) and all(
        rate > _MAX_PUBLIC_AUTOINDEX_REQUEST_RATE_PER_SECOND for rate in rates
    )


def _valid_limit_req_rates(
    directives: list[DirectiveNode],
    zone_rates: dict[str, float],
) -> list[float]:
    return [
        zone_rates[zone_name]
        for directive in directives
        if (zone_name := find_zone_name(directive.args)) in zone_rates
    ]


def _limit_conn_values_too_high(limits: list[int]) -> bool:
    return bool(limits) and all(
        limit > _MAX_PUBLIC_AUTOINDEX_CONNECTIONS for limit in limits
    )


def _valid_limit_conn_limits(directives: list[DirectiveNode]) -> list[int]:
    return [
        parsed
        for directive in directives
        if len(directive.args) >= 2
        if (parsed := parse_positive_integer(directive.args[1])) is not None
    ]


def _location_is_internal_or_named(location: BlockNode) -> bool:
    return (
        bool(location.args)
        and location.args[0].startswith("@")
        or bool(find_child_directives(location, "internal"))
    )


def _finding(directive: DirectiveNode, weaknesses: list[str]) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="medium",
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.source.file_path,
            line=directive.source.line,
        ),
        metadata={"weaknesses": ",".join(weaknesses)},
    )


__all__ = ["find_public_autoindex_rate_limit_policy_weak"]
