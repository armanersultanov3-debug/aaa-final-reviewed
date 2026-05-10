from tests.apache_helpers import (
    ApacheParseError,
    Path,
    analyze_apache_config,
    parse_apache_config,
    pytest,
    _posix_path,
    _with_backup_files_restriction,
)

def test_analyze_apache_config_does_not_report_missing_top_level_logs_when_both_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 127.0.0.1:80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert server_findings == []


def test_analyze_apache_config_reports_missing_top_level_error_log(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 127.0.0.1:80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.error_log_missing"
    assert finding.title == "Missing ErrorLog directive"


def test_analyze_apache_config_reports_missing_top_level_custom_log(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 127.0.0.1:80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.custom_log_missing"
    assert finding.title == "Missing CustomLog directive"


def test_analyze_apache_config_does_not_report_missing_top_level_error_documents_when_both_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 127.0.0.1:80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert server_findings == []


def test_analyze_apache_config_reports_missing_top_level_error_document_404(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 127.0.0.1:80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.error_document_404_missing"
    assert finding.title == "ErrorDocument 404 not configured safely"


def test_analyze_apache_config_reports_missing_top_level_error_document_500(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "Listen 127.0.0.1:80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.error_document_500_missing"
    assert finding.title == "ErrorDocument 500 not configured safely"


def test_analyze_apache_config_reports_incomplete_top_level_error_document_404(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 127.0.0.1:80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.error_document_404_missing"
    assert finding.title == "ErrorDocument 404 not configured safely"


def test_analyze_apache_config_reports_incomplete_top_level_error_document_500(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500\n"
            "Listen 127.0.0.1:80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.error_document_500_missing"
    assert finding.title == "ErrorDocument 500 not configured safely"


def test_analyze_apache_config_parse_error(tmp_path: Path) -> None:
    config_path = tmp_path / "invalid.conf"
    config_path.write_text("<VirtualHost *:80>\nServerName example.test\n", encoding="utf-8")

    result = analyze_apache_config(str(config_path))

    assert result.findings == []
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "apache_parse_error"
    assert issue.level == "error"


def test_analyze_apache_config_resolves_single_include_with_rule_relevant_directive(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "Include extra.conf",
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                ]
            )
        ),
        encoding="utf-8",
    )
    include_path.write_text("ServerTokens Full\n", encoding="utf-8")

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.server_tokens_not_prod"
    assert finding.location is not None
    assert finding.location.file_path == str(include_path)
    assert finding.location.line == 1


def test_analyze_apache_config_resolves_glob_include(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "Include conf.d/*.conf",
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                ]
            )
        ),
        encoding="utf-8",
    )
    (conf_dir / "a.conf").write_text("ServerTokens Full\n", encoding="utf-8")
    (conf_dir / "b.conf").write_text("# no-op\n", encoding="utf-8")

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.server_tokens_not_prod"
    assert finding.location is not None
    assert finding.location.file_path == str(conf_dir / "a.conf")
    assert finding.location.line == 1


def test_analyze_apache_config_resolves_nested_include(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "Include conf.d/a.conf",
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                ]
            )
        ),
        encoding="utf-8",
    )
    (conf_dir / "a.conf").write_text("Include b.conf\n", encoding="utf-8")
    (conf_dir / "b.conf").write_text("ServerTokens Full\n", encoding="utf-8")

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.server_tokens_not_prod"
    assert finding.location is not None
    assert finding.location.file_path == str(conf_dir / "b.conf")
    assert finding.location.line == 1


def test_analyze_apache_config_reports_issue_for_self_include(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "Include httpd.conf",
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.findings == []
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "apache_include_self_include"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)
    assert issue.location.line == 1


def test_analyze_apache_config_reports_issue_for_include_cycle(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "Include conf.d/a.conf",
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                ]
            )
        ),
        encoding="utf-8",
    )
    (conf_dir / "a.conf").write_text("Include b.conf\n", encoding="utf-8")
    (conf_dir / "b.conf").write_text("Include a.conf\n", encoding="utf-8")

    result = analyze_apache_config(str(config_path))

    assert result.findings == []
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "apache_include_cycle"
    assert issue.location is not None
    assert issue.location.file_path == str(conf_dir / "b.conf")
    assert issue.location.line == 1


def test_analyze_apache_config_reports_issue_for_missing_include_file(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "Include conf.d/missing.conf",
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.findings == []
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "apache_include_not_found"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)
    assert issue.location.line == 1


def test_analyze_apache_config_reports_invalid_utf8_include(tmp_path: Path) -> None:
    include_path = tmp_path / "bad.conf"
    include_path.write_bytes(b"\xff\xfe")

    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(f'Include "{_posix_path(include_path)}"\n'),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert len(result.issues) == 1
    assert result.issues[0].code == "apache_include_read_error"


def test_analyze_apache_config_ignores_missing_includeoptional_file(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "IncludeOptional conf.d/*.conf",
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.findings == []
    assert result.issues == []


def test_analyze_apache_config_reports_parse_error_in_included_file(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()
    bad_include_path = conf_dir / "bad.conf"

    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "Include conf.d/bad.conf",
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                ]
            )
        ),
        encoding="utf-8",
    )
    bad_include_path.write_text("<VirtualHost *:80>\n", encoding="utf-8")

    result = analyze_apache_config(str(config_path))

    assert result.findings == []
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "apache_include_parse_error"
    assert issue.location is not None
    assert issue.location.file_path == str(bad_include_path)


# ---------------------------------------------------------------------------
# Phase 2.1: Parser handles arbitrary block types (IfModule, Proxy, etc.)
# ---------------------------------------------------------------------------


def test_parser_accepts_ifmodule_block() -> None:
    config = (
        "<IfModule mod_ssl.c>\n"
        "    SSLEngine on\n"
        "</IfModule>\n"
    )
    ast = parse_apache_config(config)
    assert len(ast.nodes) == 1
    block = ast.nodes[0]
    assert block.name == "IfModule"
    assert block.args == ["mod_ssl.c"]
    assert len(block.children) == 1
    assert block.children[0].name == "SSLEngine"
    assert block.children[0].args == ["on"]


def test_parser_accepts_ifmodule_nested_in_directory() -> None:
    config = (
        '<Directory "/var/www">\n'
        "    AllowOverride None\n"
        "    <IfModule mod_rewrite.c>\n"
        "        RewriteEngine On\n"
        "    </IfModule>\n"
        "</Directory>\n"
    )
    ast = parse_apache_config(config)
    directory = ast.nodes[0]
    assert directory.name == "Directory"
    ifmod = directory.children[1]
    assert ifmod.name == "IfModule"
    assert ifmod.args == ["mod_rewrite.c"]
    assert ifmod.children[0].name == "RewriteEngine"


def test_parser_accepts_directory_inside_ifmodule() -> None:
    config = (
        "<IfModule mod_alias.c>\n"
        '    <Directory "/var/www/icons">\n'
        "        AllowOverride None\n"
        "        Options Indexes\n"
        "    </Directory>\n"
        "</IfModule>\n"
    )
    ast = parse_apache_config(config)
    ifmod = ast.nodes[0]
    assert ifmod.name == "IfModule"
    directory = ifmod.children[0]
    assert directory.name == "Directory"
    assert directory.children[1].args == ["Indexes"]


def test_parser_accepts_proxy_block() -> None:
    config = (
        '<Proxy "balancer://mycluster">\n'
        "    BalancerMember http://backend1\n"
        "</Proxy>\n"
    )
    ast = parse_apache_config(config)
    assert ast.nodes[0].name == "Proxy"
    assert ast.nodes[0].args == ["balancer://mycluster"]


def test_parser_accepts_if_block() -> None:
    config = (
        '<If "%{REQUEST_URI} =~ /\\.secret/">\n'
        "    Require all denied\n"
        "</If>\n"
    )
    ast = parse_apache_config(config)
    assert ast.nodes[0].name == "If"
    assert len(ast.nodes[0].children) == 1


def test_parser_accepts_limitexcept_block() -> None:
    config = (
        '<Directory "/var/www">\n'
        "    AllowOverride None\n"
        "    <LimitExcept GET POST>\n"
        "        Require all denied\n"
        "    </LimitExcept>\n"
        "</Directory>\n"
    )
    ast = parse_apache_config(config)
    limit = ast.nodes[0].children[1]
    assert limit.name == "LimitExcept"
    assert limit.args == ["GET", "POST"]


def test_parser_rejects_mismatched_unknown_blocks() -> None:
    config = (
        "<IfModule mod_ssl.c>\n"
        "    SSLEngine on\n"
        "</IfVersion>\n"
    )
    with pytest.raises(ApacheParseError, match="Mismatched closing block"):
        parse_apache_config(config)


def test_parser_rejects_unterminated_unknown_block() -> None:
    config = (
        "<IfModule mod_ssl.c>\n"
        "    SSLEngine on\n"
    )
    with pytest.raises(ApacheParseError, match="Unexpected end of input"):
        parse_apache_config(config)


def test_rules_find_directory_inside_ifmodule(tmp_path: Path) -> None:
    """Rules still find <Directory> blocks even when wrapped in <IfModule>."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "<IfModule mod_dir.c>\n"
            '    <Directory "/var/www">\n'
            "        AllowOverride None\n"
            "        Options Indexes\n"
            "    </Directory>\n"
            "</IfModule>\n"
            "ServerSignature Off\n"
            "ServerTokens Prod\n"
            "TraceEnable Off\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            'ErrorDocument 404 "/error/404.html"\n'
            'ErrorDocument 500 "/error/500.html"\n'
        ),
        encoding="utf-8",
    )
    result = analyze_apache_config(str(config_path))
    rule_ids = [f.rule_id for f in result.findings]
    assert "apache.options_indexes" in rule_ids


def test_parser_deeply_nested_unknown_blocks() -> None:
    config = (
        "<VirtualHost *:443>\n"
        "    <IfModule mod_ssl.c>\n"
        "        <Directory /var/www>\n"
        "            AllowOverride None\n"
        "            <IfModule mod_rewrite.c>\n"
        "                RewriteEngine On\n"
        "            </IfModule>\n"
        "        </Directory>\n"
        "    </IfModule>\n"
        "</VirtualHost>\n"
    )
    ast = parse_apache_config(config)
    vhost = ast.nodes[0]
    assert vhost.name == "VirtualHost"
    ifmod_ssl = vhost.children[0]
    assert ifmod_ssl.name == "IfModule"
    directory = ifmod_ssl.children[0]
    assert directory.name == "Directory"
    ifmod_rewrite = directory.children[1]
    assert ifmod_rewrite.name == "IfModule"
    assert ifmod_rewrite.children[0].name == "RewriteEngine"


def test_parser_accepts_ifversion_block() -> None:
    config = (
        "<IfVersion >= 2.4>\n"
        "    Require all granted\n"
        "</IfVersion>\n"
    )
    ast = parse_apache_config(config)
    assert len(ast.nodes) == 1
    assert ast.nodes[0].name == "IfVersion"
    assert ast.nodes[0].args == [">=", "2.4"]
    assert ast.nodes[0].children[0].name == "Require"


def test_parser_accepts_completely_unknown_block() -> None:
    """Any <Name> ... </Name> pair parses -- not just blocks in KNOWN_BLOCK_NAMES."""
    config = (
        "<CustomThing foo bar>\n"
        "    SomeDirective value\n"
        "</CustomThing>\n"
    )
    ast = parse_apache_config(config)
    assert len(ast.nodes) == 1
    block = ast.nodes[0]
    assert block.name == "CustomThing"
    assert block.args == ["foo", "bar"]
    assert block.children[0].name == "SomeDirective"


def test_rules_find_location_inside_ifmodule(tmp_path: Path) -> None:
    """Rules still find <Location> blocks when wrapped in <IfModule>."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "<IfModule mod_status.c>\n"
            '    <Location "/server-status">\n'
            "        SetHandler server-status\n"
            "    </Location>\n"
            "</IfModule>\n"
            "ServerSignature Off\n"
            "ServerTokens Prod\n"
            "TraceEnable Off\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            'ErrorDocument 404 "/error/404.html"\n'
            'ErrorDocument 500 "/error/500.html"\n'
        ),
        encoding="utf-8",
    )
    result = analyze_apache_config(str(config_path))
    rule_ids = [f.rule_id for f in result.findings]
    assert "apache.server_status_exposed" in rule_ids


# ---------------------------------------------------------------------------
# Phase 2.2: .htaccess discovery and parsing
# ---------------------------------------------------------------------------
