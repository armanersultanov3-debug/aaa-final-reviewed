from __future__ import annotations

from webconf_audit.local.nginx.effective_scope import NginxScopeKind, build_scope_graph
from tests.nginx_helpers import NginxParser, NginxTokenizer, Path, resolve_includes


def _parse_config(config_path: Path):
    tokens = NginxTokenizer(
        config_path.read_text(encoding="utf-8"),
        file_path=str(config_path),
    ).tokenize()
    return NginxParser(tokens).parse()


def test_build_scope_graph_is_deterministic_and_tracks_nested_scopes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        location /api/ {\n"
        "            if ($request_method = GET) {\n"
        "                return 204;\n"
        "            }\n"
        "            limit_except GET {\n"
        "                deny all;\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    first = build_scope_graph(_parse_config(config_path), root_file=str(config_path))
    second = build_scope_graph(_parse_config(config_path), root_file=str(config_path))

    assert [scope.scope_id for scope in first.scopes] == [scope.scope_id for scope in second.scopes]
    assert [scope.kind for scope in first.scopes] == [
        NginxScopeKind.MAIN,
        NginxScopeKind.HTTP,
        NginxScopeKind.SERVER,
        NginxScopeKind.LOCATION,
        NginxScopeKind.IF_IN_LOCATION,
        NginxScopeKind.LIMIT_EXCEPT,
    ]


def test_build_scope_graph_marks_only_affected_branch_incomplete(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        server_name broken.test;\n"
        "        location /broken/ {\n"
        "            include missing.conf;\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "    server {\n"
        "        server_name healthy.test;\n"
        "        location /ok/ {\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    ast = _parse_config(config_path)
    issues = resolve_includes(ast, config_path)
    graph = build_scope_graph(ast, issues=issues, root_file=str(config_path))

    incomplete_locations = [
        scope
        for scope in graph.scopes
        if scope.kind == NginxScopeKind.LOCATION and not scope.complete
    ]
    complete_locations = [
        scope
        for scope in graph.scopes
        if scope.kind == NginxScopeKind.LOCATION and scope.complete
    ]

    assert len(incomplete_locations) == 1
    assert incomplete_locations[0].completeness_issues == ("nginx_include_not_found",)
    assert len(complete_locations) == 1


def test_build_scope_graph_ignores_stream_servers_but_keeps_top_level_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "}\n"
        "stream {\n"
        "    server {\n"
        "        listen 9000;\n"
        "    }\n"
        "}\n"
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    graph = build_scope_graph(_parse_config(config_path), root_file=str(config_path))

    assert [scope.kind for scope in graph.scopes] == [
        NginxScopeKind.MAIN,
        NginxScopeKind.SERVER,
        NginxScopeKind.HTTP,
        NginxScopeKind.SERVER,
    ]
