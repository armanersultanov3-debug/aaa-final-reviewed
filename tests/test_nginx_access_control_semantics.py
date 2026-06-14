from __future__ import annotations

from pathlib import Path

from webconf_audit.local.nginx.access_control_semantics import resolve_effective_access_control
from webconf_audit.local.nginx.effective_scope import NginxScopeGraph, NginxScopeKind, build_scope_graph
from webconf_audit.local.nginx.include import resolve_includes
from webconf_audit.local.nginx.parser.parser import NginxParser, NginxTokenizer


def _scope_graph(tmp_path: Path, config_text: str) -> NginxScopeGraph:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config_text, encoding="utf-8")
    ast = NginxParser(NginxTokenizer(config_text, file_path=str(config_path)).tokenize()).parse()
    issues = resolve_includes(ast, config_path)
    return build_scope_graph(ast, issues=issues, root_file=str(config_path))


def _location_scope_id(scope_graph: NginxScopeGraph, selector: str) -> str:
    return next(
        scope.scope_id
        for scope in scope_graph.scopes
        if scope.kind == NginxScopeKind.LOCATION and scope.selector == selector
    )


def test_access_control_inherits_parent_allowlist_and_preserves_rule_order(
    tmp_path: Path,
) -> None:
    scope_graph = _scope_graph(
        tmp_path,
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        allow 10.20.0.0/16;\n"
        "        deny all;\n"
        "        location /admin/ { }\n"
        "    }\n"
        "}\n",
    )

    control = resolve_effective_access_control(
        scope_graph=scope_graph,
        route_scope_id=_location_scope_id(scope_graph, "/admin/"),
    )

    assert [rule.action for rule in control.address_rules] == ["allow", "deny"]
    assert [rule.subject for rule in control.address_rules] == ["10.20.0.0/16", "all"]
    assert control.classification == "ip_restricted"


def test_access_control_replaces_parent_allowlist_with_child_rules(
    tmp_path: Path,
) -> None:
    scope_graph = _scope_graph(
        tmp_path,
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        allow 10.20.0.0/16;\n"
        "        deny all;\n"
        "        location /admin/ {\n"
        "            allow 192.168.0.0/16;\n"
        "            deny all;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    control = resolve_effective_access_control(
        scope_graph=scope_graph,
        route_scope_id=_location_scope_id(scope_graph, "/admin/"),
    )

    assert [rule.subject for rule in control.address_rules] == ["192.168.0.0/16", "all"]


def test_access_control_does_not_treat_allow_all_then_deny_all_as_restrictive(
    tmp_path: Path,
) -> None:
    scope_graph = _scope_graph(
        tmp_path,
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location /admin/ {\n"
        "            allow all;\n"
        "            deny all;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    control = resolve_effective_access_control(
        scope_graph=scope_graph,
        route_scope_id=_location_scope_id(scope_graph, "/admin/"),
    )

    assert control.classification == "unprotected"


def test_access_control_auth_basic_off_cancels_inherited_basic_auth(
    tmp_path: Path,
) -> None:
    scope_graph = _scope_graph(
        tmp_path,
        "events {}\n"
        "http {\n"
        "    server {\n"
        '        auth_basic \"realm\";\n'
        "        auth_basic_user_file /etc/nginx/htpasswd;\n"
        "        location /admin/ {\n"
        "            auth_basic off;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    control = resolve_effective_access_control(
        scope_graph=scope_graph,
        route_scope_id=_location_scope_id(scope_graph, "/admin/"),
    )

    assert control.auth_basic.state == "off"
    assert control.classification == "unprotected"


def test_access_control_satisfy_any_with_auth_bypass_is_not_ip_restricted(
    tmp_path: Path,
) -> None:
    scope_graph = _scope_graph(
        tmp_path,
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        location /admin/ {\n"
        "            deny all;\n"
        '            auth_basic \"realm\";\n'
        "            auth_basic_user_file /etc/nginx/htpasswd;\n"
        "            satisfy any;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    control = resolve_effective_access_control(
        scope_graph=scope_graph,
        route_scope_id=_location_scope_id(scope_graph, "/admin/"),
    )

    assert control.satisfy == "any"
    assert control.classification == "authenticated"


def test_access_control_keeps_if_return_conditional_and_tracks_limit_except(
    tmp_path: Path,
) -> None:
    scope_graph = _scope_graph(
        tmp_path,
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        location /admin/ {\n"
        "            if ($request_method = POST) {\n"
        "                return 403;\n"
        "            }\n"
        "            limit_except GET {\n"
        "                deny all;\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    control = resolve_effective_access_control(
        scope_graph=scope_graph,
        route_scope_id=_location_scope_id(scope_graph, "/admin/"),
    )

    assert control.unconditional_return is None
    assert control.classification == "method_restricted_only"
    assert len(control.method_overrides) == 1
    assert control.method_overrides[0].allowed_methods == ("GET",)
