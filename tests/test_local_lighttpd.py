from tests.lighttpd_helpers import (
    AnalysisResult,
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdCondition,
    LighttpdDirectiveNode,
    LighttpdParseError,
    Path,
    _quote,
    analyze_lighttpd_config,
    expand_variables,
    find_server_tag_not_blank,
    find_ssl_engine_not_enabled,
    parse_lighttpd_config,
    pytest,
)

_LIGHTTPD_REDIRECT_ONLY_NOISE_RULE_IDS = frozenset(
    {
        "lighttpd.max_connections_missing",
        "lighttpd.max_request_size_missing",
        "lighttpd.missing_strict_transport_security",
        "lighttpd.missing_x_content_type_options",
        "lighttpd.url_access_deny_missing",
        "universal.missing_content_security_policy",
        "universal.missing_referrer_policy",
        "universal.missing_x_content_type_options",
        "universal.missing_x_frame_options",
    }
)


def test_parse_lighttpd_simple_config_preserves_source_locations() -> None:
    ast = parse_lighttpd_config(
        'server.document-root = "/var/www/html"\ninclude "conf.d/app.conf"\n',
        file_path="lighttpd.conf",
    )

    assert len(ast.nodes) == 2

    assignment = ast.nodes[0]
    assert isinstance(assignment, LighttpdAssignmentNode)
    assert assignment.name == "server.document-root"
    assert assignment.operator == "="
    assert assignment.value == '"/var/www/html"'
    assert assignment.source.file_path == "lighttpd.conf"
    assert assignment.source.line == 1

    directive = ast.nodes[1]
    assert isinstance(directive, LighttpdDirectiveNode)
    assert directive.name == "include"
    assert directive.args == ["conf.d/app.conf"]
    assert directive.source.file_path == "lighttpd.conf"
    assert directive.source.line == 2


def test_parse_lighttpd_reports_unterminated_quoted_string_on_start_line() -> None:
    with pytest.raises(LighttpdParseError) as exc_info:
        parse_lighttpd_config(
            'server.tag = "unterminated\nserver.port = 8080\n',
            file_path="lighttpd.conf",
        )

    assert exc_info.value.line == 1
    assert exc_info.value.file_path == "lighttpd.conf"


def test_parse_lighttpd_config_accepts_utf8_bom() -> None:
    ast = parse_lighttpd_config('\ufeffserver.tag = ""\n', file_path="lighttpd.conf")

    assert len(ast.nodes) == 1
    assignment = ast.nodes[0]
    assert isinstance(assignment, LighttpdAssignmentNode)
    assert assignment.name == "server.tag"
    assert assignment.source.file_path == "lighttpd.conf"
    assert assignment.source.line == 1


def test_ssl_engine_not_enabled_finding_uses_rule_metadata_defaults() -> None:
    ast = parse_lighttpd_config("server.port = 443\n", file_path="lighttpd.conf")

    finding = find_ssl_engine_not_enabled(ast)[0]
    meta = find_ssl_engine_not_enabled._rule_meta

    assert finding.title == meta.title
    assert finding.description == meta.description
    assert finding.recommendation == meta.recommendation


def test_server_tag_not_blank_finding_uses_rule_metadata_defaults() -> None:
    ast = parse_lighttpd_config('server.tag = "demo"\n', file_path="lighttpd.conf")

    finding = find_server_tag_not_blank(ast)[0]
    meta = find_server_tag_not_blank._rule_meta

    assert finding.title == meta.title
    assert finding.description == meta.description
    assert finding.recommendation == meta.recommendation


def test_parse_lighttpd_include_shell_with_spaces_and_quotes() -> None:
    ast = parse_lighttpd_config(
        'include_shell "python -c \\"print(\'hello world\')\\""\n',
        file_path="lighttpd.conf",
    )

    assert len(ast.nodes) == 1

    directive = ast.nodes[0]
    assert isinstance(directive, LighttpdDirectiveNode)
    assert directive.name == "include_shell"
    assert directive.args == ['python -c "print(\'hello world\')"']
    assert directive.source.file_path == "lighttpd.conf"
    assert directive.source.line == 1


def test_parse_lighttpd_config_with_condition_block() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.tag = "demo"\n'
        '    include "extra.conf"\n'
        "}\n",
        file_path="lighttpd.conf",
    )

    assert len(ast.nodes) == 1

    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.header == '$HTTP["host"] == "example.test"'
    assert block.source.file_path == "lighttpd.conf"
    assert block.source.line == 1
    assert len(block.children) == 2

    child_assignment = block.children[0]
    assert isinstance(child_assignment, LighttpdAssignmentNode)
    assert child_assignment.name == "server.tag"
    assert child_assignment.source.line == 2

    child_directive = block.children[1]
    assert isinstance(child_directive, LighttpdDirectiveNode)
    assert child_directive.name == "include"
    assert child_directive.args == ["extra.conf"]
    assert child_directive.source.line == 3


def test_parse_condition_http_host_equality() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.tag = "demo"\n'
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.condition == LighttpdCondition(
        variable='$HTTP["host"]',
        operator="==",
        value="example.test",
    )


def test_parse_condition_server_socket() -> None:
    ast = parse_lighttpd_config(
        '$SERVER["socket"] == ":443" {\n'
        '    ssl.engine = "enable"\n'
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.condition == LighttpdCondition(
        variable='$SERVER["socket"]',
        operator="==",
        value=":443",
    )


def test_parse_condition_url_regex_match() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["url"] =~ "^/api/" {\n'
        "    server.port = 9000\n"
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.condition == LighttpdCondition(
        variable='$HTTP["url"]',
        operator="=~",
        value="^/api/",
    )


def test_parse_condition_negated_regex() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] !~ "^www\\." {\n'
        "    server.port = 8080\n"
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.condition == LighttpdCondition(
        variable='$HTTP["host"]',
        operator="!~",
        value="^www\\.",
    )


def test_parse_condition_inequality() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] != "blocked.test" {\n'
        "    server.port = 8080\n"
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.condition == LighttpdCondition(
        variable='$HTTP["host"]',
        operator="!=",
        value="blocked.test",
    )


def test_parse_condition_else_block_has_no_condition() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        "    server.port = 443\n"
        "}\n"
        "else {\n"
        "    server.port = 80\n"
        "}\n",
    )
    assert len(ast.nodes) == 2
    cond_block = ast.nodes[0]
    else_block = ast.nodes[1]
    assert isinstance(cond_block, LighttpdBlockNode)
    assert cond_block.condition is not None
    assert isinstance(else_block, LighttpdBlockNode)
    assert else_block.header == "else"
    assert else_block.condition is None


def test_parse_condition_unrecognized_header_has_no_condition() -> None:
    ast = parse_lighttpd_config(
        "some_custom_block {\n"
        "    server.port = 8080\n"
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.header == "some_custom_block"
    assert block.condition is None


def test_parse_explicit_if_with_invalid_condition_errors() -> None:
    with pytest.raises(LighttpdParseError, match="Invalid conditional block header: if"):
        parse_lighttpd_config(
            "if some_custom_block {\n"
            "    server.port = 8080\n"
            "}\n",
            file_path="lighttpd.conf",
        )


def test_parse_explicit_else_if_with_invalid_condition_errors() -> None:
    with pytest.raises(LighttpdParseError, match="Invalid conditional block header: elseif"):
        parse_lighttpd_config(
            "elseif some_custom_block {\n"
            "    server.port = 8080\n"
            "}\n",
            file_path="lighttpd.conf",
        )


def test_parse_condition_existing_block_test_still_works() -> None:
    """Existing test: condition parsing does not break header field."""
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.tag = "demo"\n'
        "}\n",
        file_path="lighttpd.conf",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.header == '$HTTP["host"] == "example.test"'
    assert block.condition is not None
    assert block.condition.variable == '$HTTP["host"]'


def test_parse_condition_prefix_suffix_and_request_header() -> None:
    ast = parse_lighttpd_config(
        '$REQUEST_HEADER["X-Forwarded-Proto"] =^ "https" {\n'
        '    ssl.engine = "enable"\n'
        '}\n'
        '$HTTP["url"] =$ ".php" {\n'
        '    cgi.assign = ( ".php" => "/usr/bin/php-cgi" )\n'
        '}\n',
    )

    first = ast.nodes[0]
    second = ast.nodes[1]
    assert isinstance(first, LighttpdBlockNode)
    assert isinstance(second, LighttpdBlockNode)
    assert first.condition == LighttpdCondition(
        variable='$REQUEST_HEADER["X-Forwarded-Proto"]',
        operator="=^",
        value="https",
    )
    assert second.condition == LighttpdCondition(
        variable='$HTTP["url"]',
        operator="=$",
        value=".php",
    )


def test_parse_else_if_branch_forms() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "a.test" {\n'
        '    server.tag = "a"\n'
        '}\n'
        'elseif $HTTP["host"] == "b.test" {\n'
        '    server.tag = "b"\n'
        '}\n'
        'elsif $HTTP["host"] == "c.test" {\n'
        '    server.tag = "c"\n'
        '}\n'
        'else if $HTTP["host"] == "d.test" {\n'
        '    server.tag = "d"\n'
        '}\n'
        'else $HTTP["host"] == "e.test" {\n'
        '    server.tag = "e"\n'
        '}\n',
    )

    blocks = [node for node in ast.nodes if isinstance(node, LighttpdBlockNode)]
    assert [block.branch_kind for block in blocks] == [
        "if",
        "else_if",
        "else_if",
        "else_if",
        "else_if",
    ]
    assert all(block.condition is not None for block in blocks)


# ---------------------------------------------------------------------------
# Variable expansion
# ---------------------------------------------------------------------------


def test_expand_variables_simple_reference() -> None:
    ast = parse_lighttpd_config(
        'var.basedir = "/var/www"\n'
        'server.document-root = var.basedir\n',
    )
    issues = expand_variables(ast)
    assert issues == []
    doc_root = ast.nodes[1]
    assert isinstance(doc_root, LighttpdAssignmentNode)
    assert doc_root.value == '"/var/www"'


def test_expand_variables_concatenation() -> None:
    ast = parse_lighttpd_config(
        'var.basedir = "/var/www"\n'
        'server.document-root = var.basedir + "/htdocs"\n',
    )
    issues = expand_variables(ast)
    assert issues == []
    doc_root = ast.nodes[1]
    assert isinstance(doc_root, LighttpdAssignmentNode)
    assert doc_root.value == '"/var/www/htdocs"'


def test_expand_variables_append_operator() -> None:
    ast = parse_lighttpd_config(
        'var.x = "hello"\n'
        'var.x += " world"\n',
    )
    issues = expand_variables(ast)
    assert issues == []
    second = ast.nodes[1]
    assert isinstance(second, LighttpdAssignmentNode)
    assert second.value == '"hello world"'


def test_expand_variables_force_assign_operator() -> None:
    ast = parse_lighttpd_config(
        'var.x = "original"\n'
        'var.x := "override"\n',
    )
    issues = expand_variables(ast)
    assert issues == []
    second = ast.nodes[1]
    assert isinstance(second, LighttpdAssignmentNode)
    assert second.value == '"override"'


def test_expand_variables_inside_block() -> None:
    ast = parse_lighttpd_config(
        'var.logdir = "/var/log"\n'
        '$HTTP["host"] == "example.test" {\n'
        '    server.errorlog = var.logdir + "/error.log"\n'
        "}\n",
    )
    issues = expand_variables(ast)
    assert issues == []
    block = ast.nodes[1]
    assert isinstance(block, LighttpdBlockNode)
    errlog = block.children[0]
    assert isinstance(errlog, LighttpdAssignmentNode)
    assert errlog.value == '"/var/log/error.log"'


def test_expand_variables_undefined_reference_reports_issue() -> None:
    ast = parse_lighttpd_config(
        'server.document-root = var.missing + "/htdocs"\n',
    )
    issues = expand_variables(ast)
    assert len(issues) == 1
    assert issues[0].code == "lighttpd_undefined_variable"
    assert "var.missing" in issues[0].message
    # Value unchanged when expansion fails.
    node = ast.nodes[0]
    assert isinstance(node, LighttpdAssignmentNode)
    assert node.value == 'var.missing + "/htdocs"'


def test_expand_variables_non_var_value_unchanged() -> None:
    ast = parse_lighttpd_config(
        'server.port = 8080\n',
    )
    issues = expand_variables(ast)
    assert issues == []
    node = ast.nodes[0]
    assert isinstance(node, LighttpdAssignmentNode)
    assert node.value == "8080"


def test_variable_quote_escapes_quotes_and_backslashes() -> None:
    assert _quote('a"b\\c') == '"a\\"b\\\\c"'


def test_expand_variables_unescapes_quoted_string_tokens() -> None:
    ast = parse_lighttpd_config(
        'var.root = "/srv/\\"quoted\\""\n'
        'server.document-root = var.root + "/a\\\\b"\n',
        file_path="lighttpd.conf",
    )

    issues = expand_variables(ast)

    assert issues == []
    assignment = ast.nodes[1]
    assert isinstance(assignment, LighttpdAssignmentNode)
    assert assignment.value == '"/srv/\\"quoted\\"/a\\\\b"'


def test_expand_variables_env_reference() -> None:
    ast = parse_lighttpd_config(
        'server.document-root = env.LIGHTTPD_ROOT + "/htdocs"\n',
    )

    issues = expand_variables(ast, environ={"LIGHTTPD_ROOT": "/srv/www"})

    assert issues == []
    assignment = ast.nodes[0]
    assert isinstance(assignment, LighttpdAssignmentNode)
    assert assignment.value == '"/srv/www/htdocs"'


def test_expand_variables_builtin_cwd(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    ast = parse_lighttpd_config(
        'server.document-root = var.CWD + "/htdocs"\n',
        file_path=str(config_path),
    )

    issues = expand_variables(ast)

    assert issues == []
    assignment = ast.nodes[0]
    assert isinstance(assignment, LighttpdAssignmentNode)
    assert assignment.value == _quote(str(tmp_path) + "/htdocs")


def test_expand_variables_builtin_pid_can_be_overridden_for_deterministic_tests() -> None:
    ast = parse_lighttpd_config(
        'server.pid-file = "/run/lighttpd-" + var.PID + ".pid"\n',
    )

    issues = expand_variables(ast, builtins={"var.PID": "1234"})

    assert issues == []
    assignment = ast.nodes[0]
    assert isinstance(assignment, LighttpdAssignmentNode)
    assert assignment.value == '"/run/lighttpd-1234.pid"'


def test_expand_variables_missing_env_reference_reports_issue() -> None:
    ast = parse_lighttpd_config(
        'server.document-root = env.MISSING_ROOT + "/htdocs"\n',
    )

    issues = expand_variables(ast, environ={})

    assert len(issues) == 1
    assert issues[0].code == "lighttpd_undefined_variable"
    assert "env.MISSING_ROOT" in issues[0].message


def test_expand_variables_integration_rules_see_expanded_values(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'var.tag = ""\n'
        "server.tag = var.tag\n",
        encoding="utf-8",
    )
    result = analyze_lighttpd_config(str(config_path))
    assert isinstance(result, AnalysisResult)
    # server.tag expands to "" → should NOT trigger server_tag_not_blank.
    assert not any(
        f.rule_id == "lighttpd.server_tag_not_blank" for f in result.findings
    )


def test_expand_variables_integration_unexpanded_triggers_rule(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'var.tag = "lighttpd"\n'
        "server.tag = var.tag\n",
        encoding="utf-8",
    )
    result = analyze_lighttpd_config(str(config_path))
    assert isinstance(result, AnalysisResult)
    # server.tag expands to "lighttpd" → SHOULD trigger server_tag_not_blank.
    assert any(
        f.rule_id == "lighttpd.server_tag_not_blank" for f in result.findings
    )


def test_analyze_lighttpd_config_accepts_path_object(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\n', encoding="utf-8")

    result = analyze_lighttpd_config(config_path)

    assert isinstance(result, AnalysisResult)
    assert result.target == str(config_path)


def test_analyze_lighttpd_config_accepts_path_object_for_missing_file(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "missing-lighttpd.conf"

    result = analyze_lighttpd_config(config_path)

    assert isinstance(result, AnalysisResult)
    assert result.target == str(config_path)
    assert len(result.issues) == 1
    assert result.issues[0].code == "config_not_found"
    assert result.issues[0].location is not None
    assert result.issues[0].location.file_path == str(config_path)


def test_analyze_lighttpd_config_reports_read_error_for_invalid_utf8(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_bytes(b"\xff\xfe")

    result = analyze_lighttpd_config(str(config_path))

    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_config_read_error"


def test_analyze_lighttpd_config_accepts_utf8_bom(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\n', encoding="utf-8-sig")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "lighttpd.server_tag_not_blank" for finding in result.findings
    )


def test_analyze_lighttpd_config_suppresses_content_noise_for_redirect_only(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.modules = ( "mod_redirect" )\n'
        'url.redirect = ( "^/(.*)" => "https://example.test/$1" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(config_path)

    rule_ids = _rule_ids(result)
    assert rule_ids.isdisjoint(_LIGHTTPD_REDIRECT_ONLY_NOISE_RULE_IDS)
    assert "lighttpd.error_log_missing" in rule_ids
    assert "universal.listen_on_all_interfaces" in rule_ids


def test_analyze_lighttpd_config_keeps_content_checks_for_partial_redirect(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.modules = ( "mod_redirect" )\n'
        'server.document-root = "/srv/www/app"\n'
        'url.redirect = ( "^/old/(.*)" => "https://example.test/new/$1" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(config_path)

    rule_ids = _rule_ids(result)
    assert "lighttpd.max_request_size_missing" in rule_ids
    assert "universal.missing_x_frame_options" in rule_ids


def test_analyze_lighttpd_config_keeps_content_checks_for_mixed_redirect_pairs(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.modules = ( "mod_redirect" )\n'
        'url.redirect = ( "^/(.*)" => "https://example.test/$1", '
        '"^/api/(.*)" => "http://backend.example.test/$1" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(config_path)

    rule_ids = _rule_ids(result)
    assert "lighttpd.max_request_size_missing" in rule_ids
    assert "universal.missing_x_frame_options" in rule_ids


def _rule_ids(result: AnalysisResult) -> set[str]:
    return {finding.rule_id for finding in result.findings}
