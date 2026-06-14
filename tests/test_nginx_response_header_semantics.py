from __future__ import annotations

from webconf_audit.local.nginx.effective_scope import NginxScopeKind, build_scope_graph
from webconf_audit.local.nginx.parser.parser import NginxParser, NginxTokenizer
from webconf_audit.local.nginx.response_header_semantics import resolve_response_header_semantics


def _parse_nginx(text: str):
    tokens = NginxTokenizer(text, file_path="nginx.conf").tokenize()
    return NginxParser(tokens).parse()


def test_response_header_semantics_respect_merge_and_if_branches() -> None:
    ast = _parse_nginx(
        "http {\n"
        "    add_header Content-Security-Policy \"default-src 'self'\" always;\n"
        "    add_header_inherit merge;\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location / {\n"
        "            add_header X-Content-Type-Options nosniff;\n"
        "            if ($request_method = GET) {\n"
        "                add_header Permissions-Policy geolocation=();\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    scope_graph = build_scope_graph(ast)
    semantics = resolve_response_header_semantics(ast, scope_graph=scope_graph)

    location_scope = next(
        scope for scope in scope_graph.scopes if scope.kind == NginxScopeKind.LOCATION
    )
    effective = semantics.effective_scopes_by_id[location_scope.scope_id]

    assert [header.normalized_name for header in effective.base_headers] == [
        "x-content-type-options",
        "content-security-policy",
    ]
    assert len(effective.conditional_branches) == 1
    branch = effective.conditional_branches[0]
    assert [header.normalized_name for header in branch.headers] == [
        "permissions-policy",
        "x-content-type-options",
        "content-security-policy",
    ]


def test_response_header_semantics_track_non_always_status_applicability() -> None:
    ast = _parse_nginx(
        "server {\n"
        "    add_header X-Content-Type-Options nosniff;\n"
        "}\n"
    )
    scope_graph = build_scope_graph(ast)
    semantics = resolve_response_header_semantics(ast, scope_graph=scope_graph)
    server_scope = next(
        scope for scope in scope_graph.scopes if scope.kind == NginxScopeKind.SERVER
    )
    effective = semantics.effective_scopes_by_id[server_scope.scope_id]
    header = effective.base_headers[0]

    assert header.always is False
    assert header.applicability.all_statuses is False
    assert 200 in header.applicability.known_statuses
    assert 500 not in header.applicability.known_statuses
