"""Effective reverse-proxy route and header resolution for Nginx."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

from webconf_audit.local.nginx.effective_scope import (
    NginxScope,
    NginxScopeGraph,
    NginxScopeKind,
)
from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, SourceSpan
from webconf_audit.local.nginx.rules._variable_taint_utils import extract_variables

UpstreamFamily = Literal["proxy", "fastcgi", "grpc", "uwsgi"]
DestinationKind = Literal["literal", "variable", "named_upstream"]
HeaderOrigin = Literal["explicit", "inherited", "nginx_default"]
HeaderDisposition = Literal["set", "removed"]
ResponseHeaderDisposition = Literal["hidden", "passed", "not_filtered"]


@dataclass(frozen=True)
class ProxyRoute:
    route_id: str
    scope_id: str
    upstream_family: UpstreamFamily
    pass_directive: DirectiveNode
    destination_tokens: tuple[str, ...]
    destination_kind: DestinationKind


@dataclass(frozen=True)
class UnsupportedProxyRoute:
    scope_id: str
    directive: DirectiveNode
    reason: str


@dataclass(frozen=True)
class EffectiveHeaderValue:
    normalized_name: str
    configured_name: str
    value_tokens: tuple[str, ...]
    rendered_value: str
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str
    origin: HeaderOrigin
    disposition: HeaderDisposition


@dataclass(frozen=True)
class UnsupportedEvidence:
    kind: str
    reason: str
    source: SourceSpan
    scope_id: str
    header_name: str | None = None


@dataclass(frozen=True)
class ResponseHeaderFilter:
    normalized_name: str
    disposition: ResponseHeaderDisposition


@dataclass(frozen=True)
class ProxyHeaderResolution:
    route: ProxyRoute
    request_headers: tuple[EffectiveHeaderValue, ...]
    response_header_filters: tuple[ResponseHeaderFilter, ...]
    complete: bool
    indeterminate_reasons: tuple[str, ...]
    unsupported_evidence: tuple[UnsupportedEvidence, ...]


@dataclass(frozen=True)
class RouteContext:
    route: ProxyRoute
    route_scope: NginxScope
    server_scope: NginxScope
    location_scope: NginxScope | None
    server_names: tuple[str, ...]


@dataclass(frozen=True)
class _UpstreamFamilySpec:
    family: UpstreamFamily
    pass_directive: str
    request_directive: str
    response_hide_directive: str
    response_pass_directive: str
    default_request_headers: tuple[tuple[str, tuple[str, ...]], ...]
    built_in_hidden_headers: frozenset[str]
    legal_route_scope_kinds: frozenset[NginxScopeKind]


_LEGAL_HEADER_SCOPE_KINDS = frozenset(
    {
        NginxScopeKind.HTTP,
        NginxScopeKind.SERVER,
        NginxScopeKind.LOCATION,
    }
)
_SUPPORTED_DIRECTIVES = frozenset(
    {
        "proxy_pass",
        "fastcgi_pass",
        "grpc_pass",
        "uwsgi_pass",
    }
)
_UNSUPPORTED_UPSTREAM_DIRECTIVES = frozenset({"scgi_pass"})

_FAMILY_SPECS: dict[UpstreamFamily, _UpstreamFamilySpec] = {
    "proxy": _UpstreamFamilySpec(
        family="proxy",
        pass_directive="proxy_pass",
        request_directive="proxy_set_header",
        response_hide_directive="proxy_hide_header",
        response_pass_directive="proxy_pass_header",
        default_request_headers=(
            ("Host", ("$proxy_host",)),
            ("Connection", ("close",)),
        ),
        built_in_hidden_headers=frozenset(
            {
                "date",
                "server",
                "x-pad",
                "x-accel-expires",
                "x-accel-redirect",
                "x-accel-limit-rate",
                "x-accel-buffering",
                "x-accel-charset",
            }
        ),
        legal_route_scope_kinds=frozenset(
            {
                NginxScopeKind.LOCATION,
                NginxScopeKind.IF_IN_LOCATION,
                NginxScopeKind.LIMIT_EXCEPT,
            }
        ),
    ),
    "fastcgi": _UpstreamFamilySpec(
        family="fastcgi",
        pass_directive="fastcgi_pass",
        request_directive="fastcgi_param",
        response_hide_directive="fastcgi_hide_header",
        response_pass_directive="fastcgi_pass_header",
        default_request_headers=(("HTTP_HOST", ("$host$is_request_port$request_port",)),),
        built_in_hidden_headers=frozenset(
            {
                "status",
                "x-accel-expires",
                "x-accel-redirect",
                "x-accel-limit-rate",
                "x-accel-buffering",
                "x-accel-charset",
            }
        ),
        legal_route_scope_kinds=frozenset(
            {
                NginxScopeKind.LOCATION,
                NginxScopeKind.IF_IN_LOCATION,
            }
        ),
    ),
    "grpc": _UpstreamFamilySpec(
        family="grpc",
        pass_directive="grpc_pass",
        request_directive="grpc_set_header",
        response_hide_directive="grpc_hide_header",
        response_pass_directive="grpc_pass_header",
        default_request_headers=(
            ("Content-Length", ("$content_length",)),
            ("TE", ("$grpc_internal_trailers",)),
            ("Host", ()),
            ("Connection", ()),
            ("Proxy-Connection", ()),
            ("Transfer-Encoding", ()),
            ("Keep-Alive", ()),
            ("Expect", ()),
            ("Upgrade", ()),
        ),
        built_in_hidden_headers=frozenset(
            {
                "date",
                "server",
                "x-accel-expires",
                "x-accel-redirect",
                "x-accel-limit-rate",
                "x-accel-buffering",
                "x-accel-charset",
            }
        ),
        legal_route_scope_kinds=frozenset(
            {
                NginxScopeKind.LOCATION,
                NginxScopeKind.IF_IN_LOCATION,
            }
        ),
    ),
    "uwsgi": _UpstreamFamilySpec(
        family="uwsgi",
        pass_directive="uwsgi_pass",
        request_directive="uwsgi_param",
        response_hide_directive="uwsgi_hide_header",
        response_pass_directive="uwsgi_pass_header",
        default_request_headers=(("HTTP_HOST", ("$host$is_request_port$request_port",)),),
        built_in_hidden_headers=frozenset(
            {
                "x-accel-expires",
                "x-accel-redirect",
                "x-accel-limit-rate",
                "x-accel-buffering",
                "x-accel-charset",
            }
        ),
        legal_route_scope_kinds=frozenset(
            {
                NginxScopeKind.LOCATION,
                NginxScopeKind.IF_IN_LOCATION,
            }
        ),
    ),
}


def discover_proxy_routes(
    config_ast: ConfigAst,
    scope_graph: NginxScopeGraph,
) -> tuple[tuple[ProxyRoute, ...], tuple[UnsupportedProxyRoute, ...]]:
    routes: list[ProxyRoute] = []
    unsupported: list[UnsupportedProxyRoute] = []
    for scope in scope_graph.scopes:
        for node in scope_graph.scope_nodes.get(scope.scope_id, ()):
            if not isinstance(node, DirectiveNode):
                continue
            if node.name in _UNSUPPORTED_UPSTREAM_DIRECTIVES:
                unsupported.append(
                    UnsupportedProxyRoute(
                        scope_id=scope.scope_id,
                        directive=node,
                        reason="unsupported-upstream-module",
                    )
                )
                continue
            for spec in _FAMILY_SPECS.values():
                if node.name != spec.pass_directive:
                    continue
                if scope.kind not in spec.legal_route_scope_kinds:
                    unsupported.append(
                        UnsupportedProxyRoute(
                            scope_id=scope.scope_id,
                            directive=node,
                            reason="illegal-route-context",
                        )
                    )
                    break
                routes.append(
                    ProxyRoute(
                        route_id=_route_id(scope.scope_id, node),
                        scope_id=scope.scope_id,
                        upstream_family=spec.family,
                        pass_directive=node,
                        destination_tokens=tuple(node.args),
                        destination_kind=_destination_kind(node.args),
                    )
                )
                break
    return tuple(routes), tuple(unsupported)


def route_context(
    route: ProxyRoute,
    scope_graph: NginxScopeGraph,
) -> RouteContext:
    route_scope = scope_graph.scopes_by_id[route.scope_id]
    server_scope = _nearest_scope_of_kind(route_scope.scope_id, scope_graph, NginxScopeKind.SERVER)
    location_scope = _nearest_scope_of_kind_optional(
        route_scope.scope_id,
        scope_graph,
        NginxScopeKind.LOCATION,
    )
    server_names = _scope_server_names(server_scope, scope_graph)
    return RouteContext(
        route=route,
        route_scope=route_scope,
        server_scope=server_scope,
        location_scope=location_scope,
        server_names=server_names,
    )


def resolve_proxy_headers(
    route: ProxyRoute,
    *,
    scope_graph: NginxScopeGraph,
) -> ProxyHeaderResolution:
    spec = _FAMILY_SPECS[route.upstream_family]
    route_scope = scope_graph.scopes_by_id[route.scope_id]
    unsupported = list(_illegal_header_directives(route_scope.scope_id, scope_graph, spec))

    request_headers, request_indeterminate = _resolve_request_headers(
        route,
        scope_graph=scope_graph,
        spec=spec,
        unsupported=unsupported,
    )
    response_filters = _resolve_response_filters(
        route,
        scope_graph=scope_graph,
        spec=spec,
        unsupported=unsupported,
    )

    reasons = list(route_scope.completeness_issues)
    reasons.extend(request_indeterminate)
    complete = not reasons and route_scope.complete
    return ProxyHeaderResolution(
        route=route,
        request_headers=request_headers,
        response_header_filters=response_filters,
        complete=complete,
        indeterminate_reasons=tuple(sorted(set(reasons))),
        unsupported_evidence=tuple(unsupported),
    )


def all_route_resolutions(
    config_ast: ConfigAst,
    scope_graph: NginxScopeGraph,
) -> tuple[tuple[ProxyHeaderResolution, ...], tuple[UnsupportedProxyRoute, ...]]:
    routes, unsupported = discover_proxy_routes(config_ast, scope_graph)
    resolutions = tuple(
        resolve_proxy_headers(route, scope_graph=scope_graph)
        for route in routes
    )
    return resolutions, unsupported


def _resolve_request_headers(
    route: ProxyRoute,
    *,
    scope_graph: NginxScopeGraph,
    spec: _UpstreamFamilySpec,
    unsupported: list[UnsupportedEvidence],
) -> tuple[tuple[EffectiveHeaderValue, ...], tuple[str, ...]]:
    effective_scope_id, directives = _nearest_request_header_scope(
        route.scope_id,
        scope_graph=scope_graph,
        directive_name=spec.request_directive,
    )
    if effective_scope_id is None or not directives:
        return _default_request_headers(route, spec=spec), ()

    resolved: list[EffectiveHeaderValue] = []
    indeterminate: list[str] = []
    for directive in directives:
        if len(directive.args) < 2:
            unsupported.append(
                UnsupportedEvidence(
                    kind="unsupported-request-header",
                    reason="directive-missing-value",
                    source=directive.source,
                    scope_id=effective_scope_id,
                )
            )
            indeterminate.append("directive-missing-value")
            continue
        value_tokens = tuple(directive.args[1:])
        if spec.family in {"fastcgi", "uwsgi"} and value_tokens and value_tokens[-1] == "if_not_empty":
            unsupported.append(
                UnsupportedEvidence(
                    kind="unsupported-request-header",
                    reason="if-not-empty-flag",
                    source=directive.source,
                    scope_id=effective_scope_id,
                    header_name=directive.args[0],
                )
            )
            indeterminate.append("if-not-empty-flag")
            value_tokens = value_tokens[:-1]
        rendered_value = " ".join(value_tokens)
        resolved.append(
            EffectiveHeaderValue(
                normalized_name=_normalize_header_name(spec.family, directive.args[0]),
                configured_name=directive.args[0],
                value_tokens=value_tokens,
                rendered_value=rendered_value,
                source=directive.source,
                declared_scope_id=effective_scope_id,
                effective_scope_id=route.scope_id,
                origin="explicit" if effective_scope_id == route.scope_id else "inherited",
                disposition="removed" if rendered_value == "" else "set",
            )
        )
    return tuple(resolved), tuple(indeterminate)


def _resolve_response_filters(
    route: ProxyRoute,
    *,
    scope_graph: NginxScopeGraph,
    spec: _UpstreamFamilySpec,
    unsupported: list[UnsupportedEvidence],
) -> tuple[ResponseHeaderFilter, ...]:
    legal_chain = tuple(
        reversed(
            [
                scope
                for scope in scope_graph.parent_chain(route.scope_id)
                if scope.kind in _LEGAL_HEADER_SCOPE_KINDS
            ]
        )
    )

    current_hide: tuple[DirectiveNode, ...] | None = None
    current_pass: tuple[DirectiveNode, ...] | None = None
    hidden = set(spec.built_in_hidden_headers)
    for scope in legal_chain:
        local_hide = tuple(
            node
            for node in scope_graph.scope_nodes.get(scope.scope_id, ())
            if isinstance(node, DirectiveNode)
            and node.name == spec.response_hide_directive
            and node.args
        )
        local_pass = tuple(
            node
            for node in scope_graph.scope_nodes.get(scope.scope_id, ())
            if isinstance(node, DirectiveNode)
            and node.name == spec.response_pass_directive
            and node.args
        )

        if not local_hide and not local_pass:
            continue
        if local_hide:
            current_hide = local_hide
        if local_pass:
            current_pass = local_pass

        hidden = set(spec.built_in_hidden_headers)
        for directive in current_hide or ():
            header = directive.args[0]
            if "$" in header:
                unsupported.append(
                    UnsupportedEvidence(
                        kind="unsupported-response-header",
                        reason="dynamic-header-name",
                        source=directive.source,
                        scope_id=scope.scope_id,
                        header_name=header,
                    )
                )
                continue
            hidden.add(header.lower())
        for directive in current_pass or ():
            hidden.discard(directive.args[0].lower())

    passed = {
        directive.args[0].lower()
        for directive in (current_pass or ())
        if "$" not in directive.args[0]
    }
    known_headers = sorted(hidden | passed)
    return tuple(
        ResponseHeaderFilter(
            normalized_name=header,
            disposition=(
                "passed"
                if header in passed
                else "hidden"
                if header in hidden
                else "not_filtered"
            ),
        )
        for header in known_headers
    )


def _nearest_request_header_scope(
    route_scope_id: str,
    *,
    scope_graph: NginxScopeGraph,
    directive_name: str,
) -> tuple[str | None, tuple[DirectiveNode, ...]]:
    for scope in scope_graph.parent_chain(route_scope_id):
        if scope.kind not in _LEGAL_HEADER_SCOPE_KINDS:
            continue
        directives = tuple(
            node
            for node in scope_graph.scope_nodes.get(scope.scope_id, ())
            if isinstance(node, DirectiveNode) and node.name == directive_name
        )
        if directives:
            return scope.scope_id, directives
    return None, ()


def _default_request_headers(
    route: ProxyRoute,
    *,
    spec: _UpstreamFamilySpec,
) -> tuple[EffectiveHeaderValue, ...]:
    return tuple(
        EffectiveHeaderValue(
            normalized_name=_normalize_header_name(spec.family, name),
            configured_name=name,
            value_tokens=value_tokens,
            rendered_value=" ".join(value_tokens),
            source=route.pass_directive.source,
            declared_scope_id=route.scope_id,
            effective_scope_id=route.scope_id,
            origin="nginx_default",
            disposition="removed" if not value_tokens else "set",
        )
        for name, value_tokens in spec.default_request_headers
    )


def _illegal_header_directives(
    route_scope_id: str,
    scope_graph: NginxScopeGraph,
    spec: _UpstreamFamilySpec,
) -> tuple[UnsupportedEvidence, ...]:
    unsupported: list[UnsupportedEvidence] = []
    candidate_scopes = {
        scope.scope_id: scope
        for scope in (*scope_graph.parent_chain(route_scope_id), *scope_graph.descendants(route_scope_id))
    }
    for scope in candidate_scopes.values():
        if scope.kind in _LEGAL_HEADER_SCOPE_KINDS:
            continue
        for node in scope_graph.scope_nodes.get(scope.scope_id, ()):
            if not isinstance(node, DirectiveNode):
                continue
            if node.name not in {
                spec.request_directive,
                spec.response_hide_directive,
                spec.response_pass_directive,
            }:
                continue
            unsupported.append(
                UnsupportedEvidence(
                    kind="illegal-context-directive",
                    reason="illegal-context",
                    source=node.source,
                    scope_id=scope.scope_id,
                    header_name=node.args[0] if node.args else None,
                )
            )
    return tuple(unsupported)


def _nearest_scope_of_kind(
    scope_id: str,
    scope_graph: NginxScopeGraph,
    kind: NginxScopeKind,
) -> NginxScope:
    scope = _nearest_scope_of_kind_optional(scope_id, scope_graph, kind)
    if scope is None:
        raise ValueError(f"Scope {scope_id!r} has no ancestor of kind {kind.value!r}.")
    return scope


def _nearest_scope_of_kind_optional(
    scope_id: str,
    scope_graph: NginxScopeGraph,
    kind: NginxScopeKind,
) -> NginxScope | None:
    for scope in scope_graph.parent_chain(scope_id):
        if scope.kind == kind:
            return scope
    return None


def _scope_server_names(
    server_scope: NginxScope,
    scope_graph: NginxScopeGraph,
) -> tuple[str, ...]:
    server_names: list[str] = []
    for node in scope_graph.scope_nodes.get(server_scope.scope_id, ()):
        if not isinstance(node, DirectiveNode) or node.name != "server_name":
            continue
        server_names.extend(node.args)
    return tuple(server_names)


def _normalize_header_name(
    family: UpstreamFamily,
    configured_name: str,
) -> str:
    if family in {"fastcgi", "uwsgi"} and configured_name.upper().startswith("HTTP_"):
        return configured_name[5:].replace("_", "-").lower()
    return configured_name.lower()


def _route_id(scope_id: str, directive: DirectiveNode) -> str:
    return f"{scope_id}:{directive.name}:{directive.source.line}:{directive.source.column}"


def _destination_kind(tokens: list[str]) -> DestinationKind:
    rendered = " ".join(tokens)
    if "$" in rendered:
        return "variable"
    if len(tokens) == 1:
        token = tokens[0]
        if "://" not in token and not token.startswith("unix:") and "/" not in token:
            return "named_upstream"
    return "literal"


def header_values_by_name(
    request_headers: tuple[EffectiveHeaderValue, ...],
) -> dict[str, tuple[EffectiveHeaderValue, ...]]:
    grouped: dict[str, list[EffectiveHeaderValue]] = defaultdict(list)
    for header in request_headers:
        grouped[header.normalized_name].append(header)
    return {
        name: tuple(values)
        for name, values in grouped.items()
    }


def response_filter_map(
    filters: tuple[ResponseHeaderFilter, ...],
) -> dict[str, ResponseHeaderDisposition]:
    return {
        entry.normalized_name: entry.disposition
        for entry in filters
    }


def expression_has_variables(value: str) -> bool:
    return bool(extract_variables(value))


__all__ = [
    "EffectiveHeaderValue",
    "ProxyHeaderResolution",
    "ProxyRoute",
    "ResponseHeaderFilter",
    "RouteContext",
    "UnsupportedEvidence",
    "UnsupportedProxyRoute",
    "all_route_resolutions",
    "discover_proxy_routes",
    "expression_has_variables",
    "header_values_by_name",
    "resolve_proxy_headers",
    "response_filter_map",
    "route_context",
]
