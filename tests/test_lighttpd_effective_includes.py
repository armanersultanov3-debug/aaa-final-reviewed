from tests.lighttpd_helpers import (
    AnalysisResult,
    LighttpdAssignmentNode,
    Path,
    _fake_shell_include_result,
    _raise_regex_error,
    analyze_lighttpd_config,
    build_effective_config,
    execute_include_shell,
    parse_lighttpd_config,
    resolve_includes,
    sys,
)


# ---------------------------------------------------------------------------
# Effective config / last-wins
# ---------------------------------------------------------------------------


def test_effective_config_last_wins_for_simple_assignment() -> None:
    ast = parse_lighttpd_config(
        'server.tag = "lighttpd"\n'
        'server.tag = ""\n',
    )
    eff = build_effective_config(ast)
    directive = eff.get_global("server.tag")
    assert directive is not None
    assert directive.value == '""'


def test_effective_config_force_assign_overrides() -> None:
    ast = parse_lighttpd_config(
        'server.tag = "original"\n'
        'server.tag := "forced"\n',
    )
    eff = build_effective_config(ast)
    directive = eff.get_global("server.tag")
    assert directive is not None
    assert directive.value == '"forced"'


def test_effective_config_append_accumulates() -> None:
    ast = parse_lighttpd_config(
        'server.modules = ( "mod_access" )\n'
        'server.modules += ( "mod_status" )\n',
    )
    eff = build_effective_config(ast)
    directive = eff.get_global("server.modules")
    assert directive is not None
    assert directive.operator == "+="
    assert '"mod_access"' in directive.value
    assert '"mod_status"' in directive.value


def test_effective_config_conditional_scope_separate_from_global() -> None:
    ast = parse_lighttpd_config(
        'server.port = 80\n'
        '$SERVER["socket"] == ":443" {\n'
        '    ssl.engine = "enable"\n'
        "}\n",
    )
    eff = build_effective_config(ast)
    assert eff.get_global("server.port") is not None
    assert eff.get_global("ssl.engine") is None
    assert len(eff.conditional_scopes) == 1
    scope = eff.conditional_scopes[0]
    assert scope.condition is not None
    assert scope.condition.variable == '$SERVER["socket"]'
    assert "ssl.engine" in scope.directives
    assert scope.directives["ssl.engine"].value == '"enable"'


def test_effective_config_last_wins_inside_conditional() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.tag = "first"\n'
        '    server.tag = "second"\n'
        "}\n",
    )
    eff = build_effective_config(ast)
    assert len(eff.conditional_scopes) == 1
    scope = eff.conditional_scopes[0]
    assert scope.directives["server.tag"].value == '"second"'


def test_effective_config_nested_block_becomes_separate_scope() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.port = 8080\n'
        '    $HTTP["url"] =~ "^/api/" {\n'
        '        server.tag = "api"\n'
        "    }\n"
        "}\n",
    )
    eff = build_effective_config(ast)
    # Two scopes: the outer host block + the nested url block.
    assert len(eff.conditional_scopes) == 2
    # Nested block has its own scope with its own directive.
    url_scope = next(
        scope
        for scope in eff.conditional_scopes
        if scope.condition is not None and scope.condition.operator == "=~"
    )
    assert url_scope.condition is not None
    assert "server.tag" in url_scope.directives
    # Parent block has only its direct assignment.
    host_scope = eff.conditional_scopes[0]
    assert host_scope.condition is not None
    assert host_scope.condition.variable == '$HTTP["host"]'
    assert "server.port" in host_scope.directives
    assert "server.tag" not in host_scope.directives


def test_effective_config_sibling_nested_conditions_stay_separate() -> None:
    """Regression: sibling nested conditions must not overwrite each other."""
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    $HTTP["url"] =~ "^/api/" {\n'
        '        server.tag = "api"\n'
        "    }\n"
        '    $HTTP["url"] =~ "^/admin/" {\n'
        '        server.tag = "admin"\n'
        "    }\n"
        "}\n",
    )
    eff = build_effective_config(ast)
    # Three scopes: one parent host block + two nested url blocks.
    assert len(eff.conditional_scopes) == 3
    nested_values = [
        scope.directives["server.tag"].value
        for scope in eff.conditional_scopes
        if "server.tag" in scope.directives
    ]
    assert nested_values == ['"api"', '"admin"']


def test_effective_config_source_location_preserved() -> None:
    ast = parse_lighttpd_config(
        'server.port = 80\n'
        'server.port = 8080\n',
        file_path="lighttpd.conf",
    )
    eff = build_effective_config(ast)
    directive = eff.get_global("server.port")
    assert directive is not None
    assert directive.source.line == 2
    assert directive.source.file_path == "lighttpd.conf"


def test_effective_config_multiple_conditional_scopes() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "a.test" {\n'
        '    server.tag = "a"\n'
        "}\n"
        '$HTTP["host"] == "b.test" {\n'
        '    server.tag = "b"\n'
        "}\n",
    )
    eff = build_effective_config(ast)
    assert len(eff.conditional_scopes) == 2
    assert eff.conditional_scopes[0].directives["server.tag"].value == '"a"'
    assert eff.conditional_scopes[1].directives["server.tag"].value == '"b"'


def test_effective_config_else_block_has_no_condition() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.tag = "main"\n'
        "}\n"
        "else {\n"
        '    server.tag = "other"\n'
        "}\n",
    )
    eff = build_effective_config(ast)
    assert len(eff.conditional_scopes) == 2
    assert eff.conditional_scopes[0].condition is not None
    assert eff.conditional_scopes[1].condition is None
    assert eff.conditional_scopes[1].header == "else"


def test_execute_include_shell_captures_stdout(tmp_path: Path) -> None:
    script_path = tmp_path / "emit_config.py"
    script_path.write_text('print(\'server.tag = ""\')\n', encoding="utf-8")

    command = f'"{Path(sys.executable).as_posix()}" "{script_path.as_posix()}"'

    assert execute_include_shell(command, cwd=tmp_path) == 'server.tag = ""\n'


def test_execute_include_shell_returns_none_on_timeout(tmp_path: Path) -> None:
    script_path = tmp_path / "sleepy.py"
    script_path.write_text(
        "import time\n"
        "time.sleep(1)\n"
        "print('server.port = 8080')\n",
        encoding="utf-8",
    )

    command = f'"{Path(sys.executable).as_posix()}" "{script_path.as_posix()}"'

    assert execute_include_shell(command, timeout=0.01, cwd=tmp_path) is None


def test_execute_include_shell_returns_none_for_invalid_command() -> None:
    assert execute_include_shell("definitely-not-a-real-command --version") is None


def test_lighttpd_include_single_file_is_inlined(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text('include "extra.conf"\nserver.port = 8080\n', encoding="utf-8")
    include_path.write_text('server.tag = "included"\n', encoding="utf-8")

    ast = parse_lighttpd_config(config_path.read_text(encoding="utf-8"), file_path=str(config_path))
    issues = resolve_includes(ast, config_path)

    assert issues == []
    assert len(ast.nodes) == 2

    included_assignment = ast.nodes[0]
    assert isinstance(included_assignment, LighttpdAssignmentNode)
    assert included_assignment.name == "server.tag"
    assert included_assignment.source.file_path == str(include_path)
    assert included_assignment.source.line == 1


def test_lighttpd_include_shell_is_skipped_by_default(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.port = 8080\n',
        encoding="utf-8",
    )

    ast = parse_lighttpd_config(config_path.read_text(encoding="utf-8"), file_path=str(config_path))
    issues = resolve_includes(ast, config_path)

    assert len(issues) == 1
    assert issues[0].code == "lighttpd_include_shell_skipped"
    assert len(ast.nodes) == 1
    assert isinstance(ast.nodes[0], LighttpdAssignmentNode)
    assert ast.nodes[0].name == "server.port"


def test_lighttpd_include_shell_is_inlined_when_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.port = 8080\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.include.execute_include_shell",
        _fake_shell_include_result('server.tag = "generated"\n'),
    )

    ast = parse_lighttpd_config(config_path.read_text(encoding="utf-8"), file_path=str(config_path))
    issues = resolve_includes(ast, config_path, execute_shell=True)

    assert issues == []
    assert len(ast.nodes) == 2
    assert isinstance(ast.nodes[0], LighttpdAssignmentNode)
    assert ast.nodes[0].name == "server.tag"
    assert ast.nodes[0].source.file_path == "shell:generate-config"
    assert ast.nodes[0].source.line == 1


def test_lighttpd_include_absolute_file_path_is_resolved(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "absolute.conf"

    config_path.write_text(f'include "{include_path}"\n', encoding="utf-8")
    include_path.write_text("server.port = 8080\n", encoding="utf-8")

    ast = parse_lighttpd_config(config_path.read_text(encoding="utf-8"), file_path=str(config_path))
    issues = resolve_includes(ast, config_path)

    assert issues == []
    assert len(ast.nodes) == 1
    assert isinstance(ast.nodes[0], LighttpdAssignmentNode)
    assert ast.nodes[0].name == "server.port"
    assert ast.nodes[0].source.file_path == str(include_path)


def test_lighttpd_include_glob_is_resolved_in_sorted_order(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text('include "conf.d/*.conf"\n', encoding="utf-8")
    (conf_dir / "b.conf").write_text("server.port = 8080\n", encoding="utf-8")
    (conf_dir / "a.conf").write_text('server.tag = "a"\n', encoding="utf-8")

    ast = parse_lighttpd_config(config_path.read_text(encoding="utf-8"), file_path=str(config_path))
    issues = resolve_includes(ast, config_path)

    assert issues == []
    assert [node.name for node in ast.nodes if isinstance(node, LighttpdAssignmentNode)] == [
        "server.tag",
        "server.port",
    ]
    assert ast.nodes[0].source.file_path == str(conf_dir / "a.conf")
    assert ast.nodes[1].source.file_path == str(conf_dir / "b.conf")


def test_analyze_lighttpd_config_reports_malformed_glob_include_without_crashing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('include "conf.d/*.conf"\nserver.tag = ""\n', encoding="utf-8")

    monkeypatch.setattr("webconf_audit.local.lighttpd.include.glob.glob", _raise_regex_error)

    result = analyze_lighttpd_config(str(config_path))

    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_not_found"
    assert result.issues[0].location is not None
    assert result.issues[0].location.file_path == str(config_path)
    assert result.issues[0].location.line == 1


def test_analyze_lighttpd_config_reports_missing_include_without_crashing(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include "missing.conf"\nserver.tag = ""\nserver.port = 8080\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "lighttpd"
    assert not any(f.rule_id in {"lighttpd.dir_listing_enabled", "lighttpd.server_tag_not_blank"} for f in result.findings)
    assert len(result.issues) == 1

    issue = result.issues[0]
    assert issue.code == "lighttpd_include_not_found"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)
    assert issue.location.line == 1


def test_analyze_lighttpd_config_skips_include_shell_by_default(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.tag = ""\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_shell_skipped"
    assert not any(f.rule_id == "lighttpd.dir_listing_enabled" for f in result.findings)


def test_analyze_lighttpd_config_reports_include_shell_execution_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.tag = ""\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.include.execute_include_shell",
        _fake_shell_include_result(None),
    )

    result = analyze_lighttpd_config(str(config_path), execute_shell=True)

    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_shell_execution_failed"
    assert result.issues[0].level == "warning"
    assert not any(f.rule_id == "lighttpd.dir_listing_enabled" for f in result.findings)


def test_analyze_lighttpd_config_executes_include_shell_when_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.tag = ""\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.include.execute_include_shell",
        _fake_shell_include_result('dir-listing.activate = "enable"\n'),
    )

    result = analyze_lighttpd_config(str(config_path), execute_shell=True)

    dir_findings = [f for f in result.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
    assert len(dir_findings) == 1
    assert dir_findings[0].location is not None
    assert dir_findings[0].location.file_path == "shell:generate-config"
    assert result.issues == []
    assert result.metadata["load_context"]["edges"] == [
        {
            "source_file": str(config_path),
            "source_line": 1,
            "target_file": "shell:generate-config",
        }
    ]


def test_analyze_lighttpd_config_detects_shell_include_cycle(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.tag = ""\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.include.execute_include_shell",
        _fake_shell_include_result('include_shell "generate-config"\n'),
    )

    result = analyze_lighttpd_config(str(config_path), execute_shell=True)

    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_cycle"
    assert result.issues[0].location is not None
    assert result.issues[0].location.file_path == "shell:generate-config"
    assert result.issues[0].level == "error"


def test_analyze_lighttpd_config_reports_self_include_issue(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('include "lighttpd.conf"\nserver.tag = ""\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert not any(f.rule_id in {"lighttpd.dir_listing_enabled", "lighttpd.server_tag_not_blank"} for f in result.findings)
    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_self_include"


def test_analyze_lighttpd_config_reports_include_cycle_issue(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text('include "conf.d/a.conf"\nserver.tag = ""\n', encoding="utf-8")
    (conf_dir / "a.conf").write_text('include "b.conf"\n', encoding="utf-8")
    (conf_dir / "b.conf").write_text('include "a.conf"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert not any(f.rule_id in {"lighttpd.dir_listing_enabled", "lighttpd.server_tag_not_blank"} for f in result.findings)
    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_cycle"
    assert result.issues[0].location is not None
    assert result.issues[0].location.file_path == str(conf_dir / "b.conf")
    assert result.issues[0].location.line == 1


def test_analyze_lighttpd_config_passes_execute_shell_to_resolve_includes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\n', encoding="utf-8")
    captured: dict[str, bool] = {}

    def fake_resolve_includes(ast, config_path, load_context=None, execute_shell=False):
        captured["execute_shell"] = execute_shell
        return []

    monkeypatch.setattr("webconf_audit.local.lighttpd.resolve_includes", fake_resolve_includes)

    result = analyze_lighttpd_config(str(config_path), execute_shell=True)

    assert isinstance(result, AnalysisResult)
    assert captured == {"execute_shell": True}


def test_analyze_lighttpd_config_returns_analysis_result_for_existing_config(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.document-root = "/var/www/html"\n'
        'server.tag = ""\n'
        '$HTTP["scheme"] == "https" {\n'
        "    server.port = 443\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(config_path)
    assert result.server_type == "lighttpd"
    assert not any(f.rule_id in {"lighttpd.dir_listing_enabled", "lighttpd.server_tag_not_blank"} for f in result.findings)
    assert result.issues == []


def test_analyze_lighttpd_config_reports_dir_listing_enabled_at_top_level(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\ndir-listing.activate = "enable"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    dir_findings = [f for f in result.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
    assert len(dir_findings) == 1
    finding = dir_findings[0]
    assert finding.title == "Directory listing enabled"
    assert finding.severity == "medium"


def test_analyze_lighttpd_config_does_not_report_dir_listing_when_disabled(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\ndir-listing.activate = "disable"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert not any(f.rule_id == "lighttpd.dir_listing_enabled" for f in result.findings)


def test_analyze_lighttpd_config_reports_dir_listing_enabled_inside_block(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        '$HTTP["host"] == "example.test" {\n'
        '    dir-listing.activate = "enable"\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    dir_findings = [f for f in result.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
    assert len(dir_findings) == 1


def test_analyze_lighttpd_config_reports_dir_listing_finding_source_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\ndir-listing.activate = "enable"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    dir_findings = [f for f in result.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
    assert len(dir_findings) == 1
    finding = dir_findings[0]
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_lighttpd_config_reports_dir_listing_enabled_from_include_file(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text('server.tag = ""\ninclude "extra.conf"\n', encoding="utf-8")
    include_path.write_text('dir-listing.activate = "enable"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    dir_findings = [f for f in result.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
    assert len(dir_findings) == 1
    finding = dir_findings[0]
    assert finding.location is not None
    assert finding.location.file_path == str(include_path)
    assert finding.location.line == 1


def test_analyze_lighttpd_config_reports_missing_server_tag(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text("server.port = 8080\n", encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    tag_findings = [f for f in result.findings if f.rule_id == "lighttpd.server_tag_not_blank"]
    assert len(tag_findings) == 1
    finding = tag_findings[0]
    assert finding.title == "Server banner not suppressed"
    assert finding.severity == "low"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 1


def test_analyze_lighttpd_config_does_not_report_server_tag_when_explicitly_blank(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "lighttpd.server_tag_not_blank" for finding in result.findings
    )


def test_analyze_lighttpd_config_reports_default_server_tag_banner(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = "lighttpd"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    tag_findings = [f for f in result.findings if f.rule_id == "lighttpd.server_tag_not_blank"]
    assert len(tag_findings) == 1
    finding = tag_findings[0]
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 1


def test_analyze_lighttpd_config_reports_custom_server_tag_banner(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = "custom-banner"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    tag_findings = [f for f in result.findings if f.rule_id == "lighttpd.server_tag_not_blank"]
    assert len(tag_findings) == 1


def test_analyze_lighttpd_config_reports_server_tag_location_for_explicit_assignment(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = "custom-banner"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    tag_findings = [f for f in result.findings if f.rule_id == "lighttpd.server_tag_not_blank"]
    assert len(tag_findings) == 1
    finding = tag_findings[0]
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 1


def test_analyze_lighttpd_config_safe_server_tag_from_include_file_does_not_report(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text('include "extra.conf"\n', encoding="utf-8")
    include_path.write_text('server.tag = ""\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "lighttpd.server_tag_not_blank" for finding in result.findings
    )


def test_analyze_lighttpd_config_reports_non_blank_server_tag_from_include_file(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text('include "extra.conf"\n', encoding="utf-8")
    include_path.write_text('server.tag = "lighttpd"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    tag_findings = [f for f in result.findings if f.rule_id == "lighttpd.server_tag_not_blank"]
    assert len(tag_findings) == 1
    finding = tag_findings[0]
    assert finding.location is not None
    assert finding.location.file_path == str(include_path)
    assert finding.location.line == 1
