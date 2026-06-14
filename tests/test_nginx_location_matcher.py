from __future__ import annotations

from pathlib import Path

from webconf_audit.local.nginx.effective_scope import NginxScopeGraph, NginxScopeKind, build_scope_graph
from webconf_audit.local.nginx.include import resolve_includes
from webconf_audit.local.nginx.location_matcher import resolve_location_sample
from webconf_audit.local.nginx.parser.parser import NginxParser, NginxTokenizer


def _scope_graph(tmp_path: Path, config_text: str) -> tuple[NginxScopeGraph, str]:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config_text, encoding="utf-8")
    ast = NginxParser(NginxTokenizer(config_text, file_path=str(config_path)).tokenize()).parse()
    issues = resolve_includes(ast, config_path)
    return build_scope_graph(ast, issues=issues, root_file=str(config_path)), str(config_path)


def _server_scope_id(scope_graph: NginxScopeGraph) -> str:
    return next(scope.scope_id for scope in scope_graph.scopes if scope.kind == NginxScopeKind.SERVER)


def test_location_matcher_prefers_exact_match_over_prefix_and_regex(
    tmp_path: Path,
) -> None:
    scope_graph, _ = _scope_graph(
        tmp_path,
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location /admin/ { }\n"
        "        location ~ ^/admin/ { }\n"
        "        location = /admin/login { }\n"
        "    }\n"
        "}\n",
    )

    result = resolve_location_sample(
        scope_graph=scope_graph,
        server_scope_id=_server_scope_id(scope_graph),
        sample_uri="/admin/login",
    )

    assert result.selected_scope is not None
    assert result.selected_scope.selector == "= /admin/login"
    assert result.indeterminate_reasons == ()


def test_location_matcher_honors_prefix_no_regex_before_regex(
    tmp_path: Path,
) -> None:
    scope_graph, _ = _scope_graph(
        tmp_path,
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location ^~ /admin/ { }\n"
        "        location ~ ^/admin/users$ { }\n"
        "    }\n"
        "}\n",
    )

    result = resolve_location_sample(
        scope_graph=scope_graph,
        server_scope_id=_server_scope_id(scope_graph),
        sample_uri="/admin/users",
    )

    assert result.selected_scope is not None
    assert result.selected_scope.selector == "^~ /admin/"


def test_location_matcher_respects_merge_slashes_off(
    tmp_path: Path,
) -> None:
    scope_graph, _ = _scope_graph(
        tmp_path,
        "events {}\n"
        "http {\n"
        "    merge_slashes off;\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location = /admin//users { }\n"
        "        location /admin/ { }\n"
        "    }\n"
        "}\n",
    )

    result = resolve_location_sample(
        scope_graph=scope_graph,
        server_scope_id=_server_scope_id(scope_graph),
        sample_uri="/admin//users",
    )

    assert result.normalized_uri == "/admin//users"
    assert result.selected_scope is not None
    assert result.selected_scope.selector == "= /admin//users"


def test_location_matcher_marks_unsupported_regex_as_indeterminate(
    tmp_path: Path,
) -> None:
    scope_graph, _ = _scope_graph(
        tmp_path,
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location ~ ^(?<name>admin)$ { }\n"
        "        location / { }\n"
        "    }\n"
        "}\n",
    )

    result = resolve_location_sample(
        scope_graph=scope_graph,
        server_scope_id=_server_scope_id(scope_graph),
        sample_uri="/admin",
    )

    assert result.status == "indeterminate"
    assert "unsupported-regex-location" in result.indeterminate_reasons
