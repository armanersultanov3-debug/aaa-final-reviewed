from tests.nginx_helpers import (
    AnalysisResult,
    LoadContext,
    NginxParser,
    NginxTokenizer,
    Path,
    analyze_nginx_config,
    resolve_includes,
    threading,
)


# pipeline error handling
def test_analyze_nginx_config_returns_issue_when_config_not_found(tmp_path: Path) -> None:
    missing_config = tmp_path / "missing.conf"

    result = analyze_nginx_config(str(missing_config))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(missing_config)
    assert result.server_type == "nginx"
    assert result.findings == []
    assert len(result.issues) == 1

    issue = result.issues[0]
    assert issue.code == "config_not_found"
    assert issue.message == f"Config file not found: {missing_config}"
    assert issue.location is not None
    assert issue.location.mode == "local"
    assert issue.location.kind == "file"
    assert issue.location.file_path == str(missing_config)


def test_analyze_nginx_config_returns_issue_when_parsing_fails(tmp_path: Path) -> None:
    config_path = tmp_path / "invalid.conf"
    config_path.write_text("worker_processes 1\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(config_path)
    assert result.server_type == "nginx"
    assert result.findings == []
    assert len(result.issues) == 1

    issue = result.issues[0]
    assert issue.code == "nginx_parse_error"
    assert issue.message == "Expected ';' or '{'"
    assert issue.location is not None
    assert issue.location.mode == "local"
    assert issue.location.kind == "file"
    assert issue.location.file_path == str(config_path)
    assert issue.location.line == 1


def test_analyze_nginx_config_accepts_single_quoted_directive_argument(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "add_header Content-Security-Policy 'default-src self';\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.server_type == "nginx"
    assert result.issues == []


def test_analyze_nginx_config_reports_unterminated_single_quoted_string(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "worker_processes 1;\nadd_header X-Test 'default-src self;\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "nginx_parse_error"
    assert issue.message == "Unterminated quoted string"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)
    assert issue.location.line == 2


# happy path / basic analysis
def test_analyze_nginx_config_returns_empty_result_for_existing_file(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("worker_processes 1;\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(config_path)
    assert result.server_type == "nginx"
    assert result.findings == []
    assert result.issues == []


def test_analyze_nginx_config_accepts_pathlike_config_path(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("worker_processes 1;\n", encoding="utf-8")

    result = analyze_nginx_config(config_path)

    assert result.target == str(config_path)
    assert result.server_type == "nginx"
    assert result.issues == []


# include resolution
def test_analyze_nginx_config_resolves_simple_relative_include(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text("include extra.conf;\nworker_processes 1;\n", encoding="utf-8")
    include_path.write_text("events {}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(config_path)
    assert result.server_type == "nginx"
    assert result.findings == []
    assert result.issues == []


def test_analyze_nginx_config_resolves_glob_include(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text("include conf.d/*.conf;\nworker_processes 1;\n", encoding="utf-8")
    (conf_dir / "a.conf").write_text("events {}\n", encoding="utf-8")
    (conf_dir / "b.conf").write_text("http {}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(config_path)
    assert result.server_type == "nginx"
    assert result.findings == []
    assert result.issues == []


def test_analyze_nginx_config_resolves_absolute_include(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text(
        f'include "{include_path.as_posix()}";\n',
        encoding="utf-8",
    )
    include_path.write_text("http {\n    server_tokens on;\n}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(finding.rule_id == "nginx.server_tokens_on" for finding in result.findings)


def test_resolve_includes_inlines_include_inside_http_block(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text("http {\n    include extra.conf;\n}\n", encoding="utf-8")
    include_path.write_text("gzip on;\n", encoding="utf-8")

    tokens = NginxTokenizer(
        config_path.read_text(encoding="utf-8"), file_path=str(config_path)
    ).tokenize()
    ast = NginxParser(tokens).parse()

    resolve_includes(ast, config_path)

    assert len(ast.nodes) == 1
    http_block = ast.nodes[0]
    assert http_block.node_type == "block"
    assert http_block.name == "http"
    assert len(http_block.children) == 1
    child = http_block.children[0]
    assert child.node_type == "directive"
    assert child.name == "gzip"
    assert child.args == ["on"]


def test_resolve_includes_normalizes_load_context_paths(tmp_path: Path) -> None:
    config_dir = tmp_path / "conf"
    config_dir.mkdir()
    include_dir = tmp_path / "shared"
    include_dir.mkdir()

    config_path = config_dir / "nginx.conf"
    include_path = include_dir / "common.conf"
    config_path.write_text(
        "include ../shared/../shared/common.conf;\nworker_processes 1;\n",
        encoding="utf-8",
    )
    include_path.write_text("events {}\n", encoding="utf-8")

    tokens = NginxTokenizer(
        config_path.read_text(encoding="utf-8"),
        file_path=str(config_path),
    ).tokenize()
    ast = NginxParser(tokens).parse()
    load_context = LoadContext(root_file=str(config_path.resolve(strict=False)))

    issues = resolve_includes(ast, config_path, load_context=load_context)

    assert issues == []
    assert len(load_context.edges) == 1
    edge = load_context.edges[0]
    assert edge.source_file == str(config_path.resolve(strict=False))
    assert edge.target_file == str(include_path.resolve(strict=False))


def test_analyze_nginx_config_reports_issue_for_self_include_cycle(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("include nginx.conf;\n", encoding="utf-8")

    result_holder: dict[str, AnalysisResult] = {}
    error_holder: dict[str, BaseException] = {}

    def run_analysis() -> None:
        try:
            result_holder["result"] = analyze_nginx_config(str(config_path))
        except BaseException as exc:
            error_holder["error"] = exc

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive(), "analyze_nginx_config hung on self-include"
    assert "error" not in error_holder

    result = result_holder["result"]
    assert isinstance(result, AnalysisResult)
    assert result.issues

    issue = result.issues[0]
    assert issue.code == "nginx_include_self_include"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)


def test_analyze_nginx_config_reports_issue_for_self_include_via_glob(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("include *.conf;\n", encoding="utf-8")

    result_holder: dict[str, AnalysisResult] = {}
    error_holder: dict[str, BaseException] = {}

    def run_analysis() -> None:
        try:
            result_holder["result"] = analyze_nginx_config(str(config_path))
        except BaseException as exc:
            error_holder["error"] = exc

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive(), "analyze_nginx_config hung on self-include via glob"
    assert "error" not in error_holder

    result = result_holder["result"]
    assert isinstance(result, AnalysisResult)
    assert result.issues

    issue = result.issues[0]
    assert issue.code == "nginx_include_self_include"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)


def test_analyze_nginx_config_reports_issue_for_self_include_via_relative_path(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("include ./nginx.conf;\n", encoding="utf-8")

    result_holder: dict[str, AnalysisResult] = {}
    error_holder: dict[str, BaseException] = {}

    def run_analysis() -> None:
        try:
            result_holder["result"] = analyze_nginx_config(str(config_path))
        except BaseException as exc:
            error_holder["error"] = exc

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive(), "analyze_nginx_config hung on self-include via relative path"
    assert "error" not in error_holder

    result = result_holder["result"]
    assert isinstance(result, AnalysisResult)
    assert result.issues

    issue = result.issues[0]
    assert issue.code == "nginx_include_self_include"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)


def test_analyze_nginx_config_reports_issue_for_self_include_via_normalized_path(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    (tmp_path / "subdir").mkdir()
    config_path.write_text("include subdir/../nginx.conf;\n", encoding="utf-8")

    result_holder: dict[str, AnalysisResult] = {}
    error_holder: dict[str, BaseException] = {}

    def run_analysis() -> None:
        try:
            result_holder["result"] = analyze_nginx_config(str(config_path))
        except BaseException as exc:
            error_holder["error"] = exc

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive(), "analyze_nginx_config hung on self-include via normalized path"
    assert "error" not in error_holder

    result = result_holder["result"]
    assert isinstance(result, AnalysisResult)
    assert result.issues

    issue = result.issues[0]
    assert issue.code == "nginx_include_self_include"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)


def test_analyze_nginx_config_resolves_nested_include_from_included_file(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text("include conf.d/a.conf;\n", encoding="utf-8")
    (conf_dir / "a.conf").write_text("include b.conf;\n", encoding="utf-8")
    (conf_dir / "b.conf").write_text("server_tokens on;\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "nginx.server_tokens_on"


def test_analyze_nginx_config_reports_missing_include_and_continues_analysis(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "include missing.conf;\n"
        "http {\n"
        "    server_tokens on;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert {issue.code for issue in result.issues} == {"nginx_include_not_found"}
    assert "nginx.server_tokens_on" in {finding.rule_id for finding in result.findings}


def test_analyze_nginx_config_reports_include_parse_error_and_continues_analysis(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    include_path = tmp_path / "broken.conf"
    config_path.write_text(
        "include broken.conf;\n"
        "http {\n"
        "    server_tokens on;\n"
        "}\n",
        encoding="utf-8",
    )
    include_path.write_text("events {\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert {issue.code for issue in result.issues} == {"nginx_include_parse_error"}
    assert "nginx.server_tokens_on" in {finding.rule_id for finding in result.findings}


def test_analyze_nginx_config_reports_issue_for_mutual_include_cycle(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text("include conf.d/a.conf;\n", encoding="utf-8")
    (conf_dir / "a.conf").write_text("include b.conf;\n", encoding="utf-8")
    (conf_dir / "b.conf").write_text("include a.conf;\n", encoding="utf-8")

    result_holder: dict[str, AnalysisResult] = {}
    error_holder: dict[str, BaseException] = {}

    def run_analysis() -> None:
        try:
            result_holder["result"] = analyze_nginx_config(str(config_path))
        except BaseException as exc:
            error_holder["error"] = exc

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive(), "analyze_nginx_config hung on mutual include cycle"
    assert "error" not in error_holder

    result = result_holder["result"]
    assert isinstance(result, AnalysisResult)
    assert result.issues

    issue = result.issues[0]
    assert issue.code == "nginx_include_cycle"
