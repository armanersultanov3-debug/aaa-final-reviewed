from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import AstNode, BlockNode
from webconf_audit.local.nginx.parser.parser import NginxParser, NginxTokenizer
from webconf_audit.local.nginx.rules._variable_taint_utils import TaintAnalyzer


def test_nginx_variable_taint_detects_builtin_user_controlled_variables() -> None:
    analyzer, location_block = _analyzer_and_location(
        "http {\n"
        "    server {\n"
        "        location / {\n"
        "            return 200 ok;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    assert analyzer.is_user_controlled("$arg_target", location_block)
    assert analyzer.is_user_controlled("$args", location_block)
    assert analyzer.is_user_controlled("$http_x_forwarded_host", location_block)
    assert analyzer.is_user_controlled("$cookie_session", location_block)
    assert analyzer.is_user_controlled("$request_method", location_block)
    assert not analyzer.is_user_controlled("$uri", location_block)
    assert analyzer.is_user_controlled("$uri", location_block, in_proxy_pass_host=True)


def test_nginx_variable_taint_resolves_set_assignments() -> None:
    analyzer, location_block = _analyzer_and_location(
        "http {\n"
        "    server {\n"
        "        set $dest $arg_target;\n"
        "        location / {\n"
        "            proxy_pass http://$dest;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    assert analyzer.is_user_controlled("$dest", location_block)


def test_nginx_variable_taint_resolves_multi_hop_set_assignments() -> None:
    analyzer, location_block = _analyzer_and_location(
        "http {\n"
        "    server {\n"
        "        set $backend $upstream;\n"
        "        set $upstream $arg_target;\n"
        "        location / {\n"
        "            proxy_pass http://$backend;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    assert analyzer.is_user_controlled("$backend", location_block)


def test_nginx_variable_taint_resolves_user_controlled_map_inputs() -> None:
    analyzer, location_block = _analyzer_and_location(
        "http {\n"
        "    map $arg_role $backend {\n"
        "        default upstream_a;\n"
        "        admin upstream_b;\n"
        "    }\n"
        "    server {\n"
        "        location / {\n"
        "            proxy_pass http://$backend;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    assert analyzer.is_user_controlled("$backend", location_block)


def test_nginx_variable_taint_handles_recursive_set_cycles() -> None:
    analyzer, location_block = _analyzer_and_location(
        "http {\n"
        "    server {\n"
        "        set $a $b;\n"
        "        set $b $a;\n"
        "        location / {\n"
        "            proxy_pass http://$a;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    assert not analyzer.is_user_controlled("$a", location_block)
    assert not analyzer.is_user_controlled("$b", location_block)


def test_nginx_variable_taint_treats_geo_and_split_clients_outputs_as_safe() -> None:
    analyzer, location_block = _analyzer_and_location(
        "http {\n"
        "    geo $geo_bucket {\n"
        "        default 0;\n"
        "    }\n"
        "    split_clients \"$request_id\" $bucket {\n"
        "        100% stable;\n"
        "    }\n"
        "    server {\n"
        "        location / {\n"
        "            return 200 ok;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    assert not analyzer.is_user_controlled("$geo_bucket", location_block)
    assert not analyzer.is_user_controlled("$bucket", location_block)


def test_nginx_variable_taint_prefers_location_scope_over_server_scope() -> None:
    analyzer, location_block = _analyzer_and_location(
        "http {\n"
        "    server {\n"
        "        set $backend $arg_target;\n"
        "        location /safe {\n"
        "            set $backend static_backend;\n"
        "            proxy_pass http://$backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        location_arg="/safe",
    )

    assert not analyzer.is_user_controlled("$backend", location_block)


def _analyzer_and_location(
    config_text: str,
    *,
    location_arg: str = "/",
) -> tuple[TaintAnalyzer, BlockNode]:
    tokens = NginxTokenizer(config_text, file_path="nginx.conf").tokenize()
    config_ast = NginxParser(tokens).parse()
    analyzer = TaintAnalyzer(config_ast)
    location_block = _find_first_block(config_ast.nodes, "location", location_arg)
    return analyzer, location_block


def _find_first_block(
    nodes: list[AstNode],
    name: str,
    first_arg: str,
) -> BlockNode:
    for node in nodes:
        if isinstance(node, BlockNode):
            if node.name == name and node.args and node.args[0] == first_arg:
                return node
            nested = _find_first_block_or_none(node.children, name, first_arg)
            if nested is not None:
                return nested
    raise AssertionError(f"Could not find block {name!r} with first arg {first_arg!r}")


def _find_first_block_or_none(
    nodes: list[AstNode],
    name: str,
    first_arg: str,
) -> BlockNode | None:
    for node in nodes:
        if not isinstance(node, BlockNode):
            continue
        if node.name == name and node.args and node.args[0] == first_arg:
            return node
        nested = _find_first_block_or_none(node.children, name, first_arg)
        if nested is not None:
            return nested
    return None
