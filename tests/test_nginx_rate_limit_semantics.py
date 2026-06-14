from __future__ import annotations

from fractions import Fraction

from tests.nginx_helpers import NginxParser, NginxTokenizer, Path, resolve_includes
from webconf_audit.local.nginx.effective_scope import build_scope_graph
from webconf_audit.local.nginx.rate_limit_semantics import resolve_rate_limit_semantics


def _parse_config(config_path: Path):
    tokens = NginxTokenizer(
        config_path.read_text(encoding="utf-8"),
        file_path=str(config_path),
    ).tokenize()
    return NginxParser(tokens).parse()


def _resolve_semantics(config_path: Path):
    ast = _parse_config(config_path)
    issues = resolve_includes(ast, config_path)
    scope_graph = build_scope_graph(ast, issues=issues, root_file=str(config_path))
    return resolve_rate_limit_semantics(ast, scope_graph=scope_graph)


def test_resolve_rate_limit_semantics_normalizes_rate_exactly(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=minute:10m rate=60r/m;\n"
        "    limit_req_zone $binary_remote_addr zone=second:10m rate=1r/s;\n"
        "    server { server_name api.example.test; }\n"
        "}\n",
        encoding="utf-8",
    )

    semantics = _resolve_semantics(config_path)

    minute_rate = semantics.request_zones_by_name["minute"].rate.requests_per_second
    second_rate = semantics.request_zones_by_name["second"].rate.requests_per_second

    assert minute_rate == Fraction(1, 1)
    assert second_rate == Fraction(1, 1)
    assert minute_rate == second_rate


def test_resolve_rate_limit_semantics_uses_exact_list_replacement_and_scalar_inheritance(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=global_req:10m rate=10r/s;\n"
        "    limit_req_zone $binary_remote_addr zone=api_req:10m rate=5r/s;\n"
        "    limit_conn_zone $binary_remote_addr zone=global_conn:10m;\n"
        "    limit_conn_zone $binary_remote_addr zone=api_conn:10m;\n"
        "    limit_req zone=global_req burst=20;\n"
        "    limit_conn global_conn 30;\n"
        "    limit_req_status 429;\n"
        "    limit_req_log_level notice;\n"
        "    server {\n"
        "        server_name api.example.test;\n"
        "        location /v1/ {\n"
        "            limit_req zone=api_req burst=5 nodelay;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    semantics = _resolve_semantics(config_path)
    server_scope = next(
        scope
        for scope in semantics.scope_graph.scopes
        if scope.kind.value == "server"
    )
    location_scope = next(
        scope
        for scope in semantics.scope_graph.scopes
        if scope.kind.value == "location"
    )

    server_effective = semantics.effective_scopes_by_id[server_scope.scope_id]
    location_effective = semantics.effective_scopes_by_id[location_scope.scope_id]

    assert [entry.zone_name for entry in server_effective.request_limits] == ["global_req"]
    assert [entry.zone_name for entry in server_effective.connection_limits] == [
        "global_conn"
    ]
    assert [entry.zone_name for entry in location_effective.request_limits] == ["api_req"]
    assert [entry.zone_name for entry in location_effective.connection_limits] == [
        "global_conn"
    ]
    assert location_effective.request_status == 429
    assert location_effective.request_log_level == "notice"


def test_resolve_rate_limit_semantics_ignores_if_in_location_directives(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    server {\n"
        "        server_name api.example.test;\n"
        "        location /v1/ {\n"
        "            if ($request_method = POST) {\n"
        "                limit_req zone=perip burst=5;\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    semantics = _resolve_semantics(config_path)
    location_scope = next(
        scope
        for scope in semantics.scope_graph.scopes
        if scope.kind.value == "location"
    )
    effective = semantics.effective_scopes_by_id[location_scope.scope_id]

    assert effective.request_limits == ()
    assert any(
        entry.reason == "illegal-context" and entry.directive_name == "limit_req"
        for entry in semantics.unsupported_evidence
    )


def test_resolve_rate_limit_semantics_marks_duplicate_incompatible_zone_definitions(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    limit_req_zone $server_name zone=perip:10m rate=10r/s;\n"
        "    server {\n"
        "        server_name api.example.test;\n"
        "        location /v1/ {\n"
        "            limit_req zone=perip burst=5;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    semantics = _resolve_semantics(config_path)
    location_scope = next(
        scope
        for scope in semantics.scope_graph.scopes
        if scope.kind.value == "location"
    )
    effective = semantics.effective_scopes_by_id[location_scope.scope_id]

    assert "perip" not in semantics.request_zones_by_name
    assert any(
        entry.reason == "duplicate-incompatible-zone-definition"
        for entry in semantics.unsupported_evidence
    )
    assert "request-zone-definition-unresolved" in effective.indeterminate_reasons
