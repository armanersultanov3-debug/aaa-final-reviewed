"""nginx.http3_alt_svc_review -- opt-in HTTP/3 advertisement review."""

from __future__ import annotations

from collections import OrderedDict

from webconf_audit.local.nginx.effective_scope import (
    NginxScope,
    NginxScopeGraph,
    NginxScopeKind,
    build_scope_graph,
)
from webconf_audit.local.nginx.parser.ast import (
    ConfigAst,
    DirectiveNode,
    find_child_directives,
)
from webconf_audit.local.nginx.response_header_semantics import (
    EffectiveResponseHeader,
    NginxResponseHeaderSemantics,
    resolve_response_header_semantics,
)
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cis_nginx_v3_0_0

RULE_ID = "nginx.http3_alt_svc_review"

_MAX_REPORTED_VALUE_LEN = 240


@rule(
    rule_id=RULE_ID,
    title="HTTP/3 and Alt-Svc configuration needs operator review",
    severity="info",
    description=(
        "A QUIC listener is configured. Static analysis can report the "
        "effective HTTP/3 and Alt-Svc settings but cannot prove deployed "
        "QUIC reachability or client discovery."
    ),
    recommendation=(
        "Verify the HTTP/3 module, UDP reachability, effective http3 setting, "
        "and Alt-Svc protocol, port, and lifetime against deployment intent."
    ),
    category="local",
    server_type="nginx",
    tags=("policy-review", "http3", "headers", "tls"),
    standards=(
        cis_nginx_v3_0_0(
            "4.1.12",
            coverage="partial",
            note=(
                "Surfaces the QUIC listener, effective http3 state, and "
                "Alt-Svc advertisement for operator review; runtime HTTP/3 "
                "is not proven."
            ),
        ),
    ),
    order=284,
)
def find_http3_alt_svc_review(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    scope_graph = build_scope_graph(config_ast)
    semantics = resolve_response_header_semantics(config_ast, scope_graph=scope_graph)

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header", "add_header_inherit", "http3"},
    ):
        quic_listeners = [
            directive
            for directive in find_child_directives(server_block, "listen")
            if any(arg.lower() == "quic" for arg in directive.args)
        ]
        if not quic_listeners:
            continue

        server_scope = scope_graph.scope_for_block(server_block)
        findings.append(
            _build_finding(
                listener=quic_listeners[0],
                http3_state=_effective_http3_state(
                    server_block,
                    inherited_directives,
                ),
                alt_svc_text=_format_alt_svc_state(
                    server_scope=server_scope,
                    scope_graph=scope_graph,
                    semantics=semantics,
                ),
            ),
        )

    return findings


def _effective_http3_state(
    server_block,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> str:
    directives = effective_child_directives(
        server_block,
        "http3",
        inherited_directives,
    )
    if not directives or not directives[-1].args:
        return "http3 on (default)"
    return f"http3 {' '.join(directives[-1].args)}"


def _format_alt_svc_state(
    *,
    server_scope: NginxScope,
    scope_graph: NginxScopeGraph,
    semantics: NginxResponseHeaderSemantics,
) -> str:
    observations: OrderedDict[
        tuple[str | None, int | None, str],
        tuple[EffectiveResponseHeader, list[str]],
    ] = OrderedDict()
    missing_scopes: list[str] = []

    for scope_label, headers in _iter_response_scope_headers(
        server_scope=server_scope,
        scope_graph=scope_graph,
        semantics=semantics,
    ):
        alt_svc_headers = [
            header
            for header in headers
            if header.normalized_name == "alt-svc"
            if header.rendered_static_value
        ]
        if not alt_svc_headers:
            missing_scopes.append(scope_label)
            continue

        for header in alt_svc_headers:
            value = header.rendered_static_value
            key = (
                header.source.file_path,
                header.source.line,
                value,
            )
            if key not in observations:
                observations[key] = (header, [])
            observations[key][1].append(scope_label)

    if not observations:
        return (
            "effective Alt-Svc header is missing from all reviewed "
            "server/location scopes"
        )

    rendered_observations = [
        _format_observation(header, value=key[2], scopes=scopes)
        for key, (header, scopes) in observations.items()
    ]
    text = "effective Alt-Svc observations: " + " | ".join(rendered_observations)
    if missing_scopes:
        text += "; scopes without effective Alt-Svc: " + ", ".join(missing_scopes)
    return text


def _iter_response_scope_headers(
    *,
    server_scope: NginxScope,
    scope_graph: NginxScopeGraph,
    semantics: NginxResponseHeaderSemantics,
) -> list[tuple[str, tuple[EffectiveResponseHeader, ...]]]:
    scopes: list[tuple[str, tuple[EffectiveResponseHeader, ...]]] = [
        (
            "server",
            semantics.effective_scopes_by_id[server_scope.scope_id].base_headers,
        )
    ]
    for scope in scope_graph.descendants(server_scope.scope_id):
        if scope.kind != NginxScopeKind.LOCATION:
            continue
        effective_scope = semantics.effective_scopes_by_id[scope.scope_id]
        scopes.append(
            (
                _scope_label(scope, scope_graph=scope_graph, server_scope_id=server_scope.scope_id),
                effective_scope.base_headers,
            )
        )
        for branch in effective_scope.conditional_branches:
            branch_scope = scope_graph.scopes_by_id[branch.branch_scope_id]
            scopes.append(
                (
                    _scope_label(
                        branch_scope,
                        scope_graph=scope_graph,
                        server_scope_id=server_scope.scope_id,
                    ),
                    branch.headers,
                )
            )
    return scopes


def _scope_label(
    scope: NginxScope,
    *,
    scope_graph: NginxScopeGraph,
    server_scope_id: str,
) -> str:
    if scope.scope_id == server_scope_id:
        return "server"

    segments: list[str] = []
    current: NginxScope | None = scope
    while current is not None and current.scope_id != server_scope_id:
        if current.block is not None:
            segments.append(" ".join((current.block.name, *current.block.args)).strip())
        current = (
            scope_graph.scopes_by_id.get(current.parent_id)
            if current.parent_id is not None
            else None
        )
    return " > ".join(reversed(segments))


def _format_observation(
    header: EffectiveResponseHeader,
    *,
    value: str,
    scopes: list[str],
) -> str:
    displayed_value = (
        value[:_MAX_REPORTED_VALUE_LEN] + "..."
        if len(value) > _MAX_REPORTED_VALUE_LEN
        else value
    )
    source = header.source.file_path or "<unknown file>"
    return (
        f"{displayed_value} at {source}, line {header.source.line} "
        f"(effective in {', '.join(scopes)})"
    )


def _build_finding(
    *,
    listener: DirectiveNode,
    http3_state: str,
    alt_svc_text: str,
) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="HTTP/3 and Alt-Svc configuration needs operator review",
        severity="info",
        description=(
            f"QUIC listener found; effective {http3_state}; "
            f"{alt_svc_text}. Static analysis does not prove runtime HTTP/3."
        ),
        recommendation=(
            "Verify the HTTP/3 module, UDP reachability, effective http3 "
            "setting, and Alt-Svc protocol, port, and lifetime against "
            "deployment intent."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=listener.source.file_path,
            line=listener.source.line,
        ),
    )


__all__ = ["find_http3_alt_svc_review"]
