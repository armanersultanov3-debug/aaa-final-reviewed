from __future__ import annotations

from webconf_audit.local.nginx.effective_scope import build_scope_graph
from webconf_audit.local.nginx.include import resolve_includes
from webconf_audit.local.nginx.logging_semantics import resolve_logging_semantics
from tests.nginx_helpers import NginxParser, NginxTokenizer, Path


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
    return resolve_logging_semantics(ast, scope_graph=scope_graph)


def test_resolve_logging_semantics_tracks_nested_access_and_error_scopes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        '    log_format main_json escape=json "$time_iso8601 ${request_id}$request_id_suffix";\n'
        "    server {\n"
        "        server_name example.test;\n"
        "        location /api/ {\n"
        "            access_log /var/log/nginx/api.log main_json if=$loggable;\n"
        "            if ($request_method = GET) {\n"
        "                access_log /var/log/nginx/branch.log;\n"
        "                error_log /var/log/nginx/ignored.log info;\n"
        "            }\n"
        "            limit_except POST {\n"
        "                access_log off;\n"
        "            }\n"
        "            error_log /var/log/nginx/location-error.log notice;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    semantics = _resolve_semantics(config_path)
    scopes_by_kind: dict[str, list[object]] = {}
    for scope in semantics.scope_graph.scopes:
        scopes_by_kind.setdefault(scope.kind.value, []).append(scope)

    server_scope = scopes_by_kind["server"][0]
    location_scope = scopes_by_kind["location"][0]
    if_scope = scopes_by_kind["if_in_location"][0]
    limit_except_scope = scopes_by_kind["limit_except"][0]

    server_effective = semantics.effective_scopes_by_id[server_scope.scope_id]
    location_effective = semantics.effective_scopes_by_id[location_scope.scope_id]
    if_effective = semantics.effective_scopes_by_id[if_scope.scope_id]
    limit_except_effective = semantics.effective_scopes_by_id[limit_except_scope.scope_id]

    assert server_effective.access_state == "enabled"
    assert server_effective.access_logs[0].origin == "nginx_default"
    assert server_effective.access_logs[0].format_name == "combined"
    assert server_effective.error_logs[0].origin == "nginx_default"
    assert server_effective.error_logs[0].threshold == "error"

    assert location_effective.access_logs[0].raw_path == "/var/log/nginx/api.log"
    assert location_effective.access_logs[0].format_name == "main_json"
    assert location_effective.access_logs[0].condition_kind == "dynamic"
    assert location_effective.error_logs[0].raw_path == "/var/log/nginx/location-error.log"
    assert location_effective.error_logs[0].threshold == "notice"

    assert if_effective.access_logs[0].raw_path == "/var/log/nginx/branch.log"
    assert if_effective.access_logs[0].format_name == "combined"
    assert if_effective.error_logs[0].raw_path == "/var/log/nginx/location-error.log"

    assert limit_except_effective.access_state == "off"
    assert limit_except_effective.access_logs == ()

    assert any(
        entry.reason == "illegal-context" and entry.directive_name == "error_log"
        for entry in semantics.unsupported_evidence
    )


def test_resolve_logging_semantics_marks_ambiguous_same_level_access_logs_unknown(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        access_log off;\n"
        "        access_log /var/log/nginx/access.log main;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    semantics = _resolve_semantics(config_path)
    server_scope = next(
        scope for scope in semantics.scope_graph.scopes if scope.kind.value == "server"
    )
    effective = semantics.effective_scopes_by_id[server_scope.scope_id]

    assert effective.access_state == "unknown"
    assert effective.access_logs == ()
    assert "ambiguous_access_log_configuration" in effective.indeterminate_reasons


def test_resolve_logging_semantics_parses_exact_variables_and_built_in_formats(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        '    log_format main escape=json "$time_iso8601" "${request_id}$request_id_suffix" "$http_authorization";\n'
        "    server {\n"
        "        access_log /var/log/nginx/access.log main;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    semantics = _resolve_semantics(config_path)

    assert "combined" in semantics.format_definitions
    assert semantics.format_definitions["combined"].origin == "nginx_builtin"

    main = semantics.format_definitions["main"]
    assert main.escape_mode == "json"
    assert main.variables == frozenset(
        {
            "$time_iso8601",
            "$request_id",
            "$request_id_suffix",
            "$http_authorization",
        }
    )
    assert "$request_id_suffix" in main.variables
    assert "$request_id" in main.variables
