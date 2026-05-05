from tests.apache_helpers import (
    ApacheParseError,
    Path,
    analyze_apache_config,
    find_context_sensitive_directives,
    parse_apache_config,
    pytest,
    _SAFE_APACHE_CIS_BASELINE_LINES,
    _SAFE_SECURITY_HEADER_BASELINE_LINES,
    _with_backup_files_restriction,
)

def test_context_sensitive_directives_normalizes_target_contexts() -> None:
    ast = parse_apache_config(
        '<Directory "/var/www">\n'
        "    Options Indexes\n"
        "</Directory>\n",
    )

    matches = find_context_sensitive_directives(
        ast.nodes,
        directive_name="options",
        target_contexts=frozenset({"Directory"}),
        token_predicate=lambda args: "Indexes" in args,
    )

    assert len(matches) == 1
    assert matches[0][1] == "directory"


def test_analyze_apache_config_success(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    'ServerRoot "/etc/httpd"',
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "Listen 127.0.0.1:80",
                    "<VirtualHost *:80>",
                    "    ServerName example.test",
                    '    <Directory "/var/www/html">',
                    "        AllowOverride None",
                    "        Options -Indexes",
                    "        Require all granted",
                    "    </Directory>",
                    '    <Location "/status">',
                    "        SetHandler server-status",
                    "    </Location>",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.mode == "local"
    assert result.server_type == "apache"
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert server_findings == []
    assert result.issues == []


def test_analyze_apache_config_accepts_files_match_block(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            [
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                '<FilesMatch "\\.(bak|old|backup|orig|save|swp|tmp)$">',
                "    Require all denied",
                "</FilesMatch>",
                *_SAFE_APACHE_CIS_BASELINE_LINES,
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.mode == "local"
    assert result.server_type == "apache"
    assert result.findings == []
    assert result.issues == []


def test_analyze_apache_config_accepts_nested_files_match_block(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            [
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                "Listen 127.0.0.1:80",
                *_SAFE_SECURITY_HEADER_BASELINE_LINES,
                *_SAFE_APACHE_CIS_BASELINE_LINES,
                "<VirtualHost *:80>",
                "    ServerName example.test",
                '    <Directory "/var/www/html">',
                "        AllowOverride None",
                "        Options -Indexes",
                '        <FilesMatch "\\.(bak|old|backup|orig|save|swp|tmp)$">',
                "            Require all denied",
                "        </FilesMatch>",
                "    </Directory>",
                "</VirtualHost>",
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.mode == "local"
    assert result.server_type == "apache"
    apache_findings = [f for f in result.findings if f.rule_id.startswith("apache.")]
    assert apache_findings == []
    assert result.issues == []


def test_analyze_apache_config_does_not_report_backup_temp_files_when_denied(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            [
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                '<FilesMatch "\\.(bak|old|backup|orig|save|swp|tmp)$">',
                "    Require all denied",
                "</FilesMatch>",
                *_SAFE_APACHE_CIS_BASELINE_LINES,
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_apache_parser_mismatched_closing_tag() -> None:
    config_text = "\n".join(
        [
            "<VirtualHost *:80>",
            "</Directory>",
        ]
    )

    with pytest.raises(ApacheParseError):
        parse_apache_config(config_text, file_path="httpd.conf")


def test_apache_parser_mismatched_files_match_closing_tag() -> None:
    config_text = "\n".join(
        [
            '<FilesMatch "\\.(bak|old|backup|orig|save|swp|tmp)$">',
            "</Directory>",
        ]
    )

    with pytest.raises(ApacheParseError):
        parse_apache_config(config_text, file_path="httpd.conf")


def test_analyze_apache_config_missing_file(tmp_path: Path) -> None:
    missing_config = tmp_path / "missing.conf"

    result = analyze_apache_config(str(missing_config))

    assert result.findings == []
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "config_not_found"
    assert issue.level == "error"


def test_analyze_apache_config_reports_read_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text("ServerSignature Off\n", encoding="utf-8")
    original_read_text = Path.read_text

    def failing_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if self == config_path:
            raise OSError("Permission denied")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing_read_text)

    result = analyze_apache_config(str(config_path))

    assert result.findings == []
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "apache_config_read_error"
    assert "Cannot read config file" in issue.message
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)


def test_analyze_apache_config_reports_decode_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text("ServerSignature Off\n", encoding="utf-8")
    original_read_text = Path.read_text

    def failing_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if self == config_path:
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing_read_text)

    result = analyze_apache_config(str(config_path))

    assert result.findings == []
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "apache_config_read_error"
    assert "Cannot decode config file" in issue.message
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)


def test_analyze_apache_config_reports_missing_backup_temp_files_restriction(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            [
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                *_SAFE_APACHE_CIS_BASELINE_LINES,
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.backup_temp_files_not_restricted"
    assert finding.title == "Backup/temp files not restricted"


def test_analyze_apache_config_reports_backup_temp_files_match_without_deny(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            [
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                '<FilesMatch "\\.(bak|old|backup|orig|save|swp|tmp)$">',
                "    Require all granted",
                "</FilesMatch>",
                *_SAFE_APACHE_CIS_BASELINE_LINES,
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.backup_temp_files_not_restricted"
    assert finding.title == "Backup/temp files not restricted"


def test_analyze_apache_config_reports_non_extension_files_match_pattern(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            [
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                '<FilesMatch "^backup-old-swp-notes$">',
                "    Require all denied",
                "</FilesMatch>",
                *_SAFE_APACHE_CIS_BASELINE_LINES,
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.backup_temp_files_not_restricted"
    assert finding.title == "Backup/temp files not restricted"


def test_analyze_apache_config_reports_missing_server_signature(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerTokens Prod",
                    "TraceEnable Off",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "Listen 127.0.0.1:80",
                    "<VirtualHost *:80>",
                    "    ServerName example.test",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.server_signature_not_off"
    assert finding.title == "ServerSignature not set to Off"


def test_analyze_apache_config_reports_unsafe_server_signature(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature On\n"
            "ServerTokens Prod\n"
            "TraceEnable Off\n"
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
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.server_signature_not_off"
    assert finding.title == "ServerSignature not set to Off"


def test_analyze_apache_config_reports_missing_server_tokens(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
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
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.server_tokens_not_prod"
    assert finding.title == "ServerTokens not set to Prod"


def test_analyze_apache_config_reports_unsafe_server_tokens(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Full\n"
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
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.server_tokens_not_prod"
    assert finding.title == "ServerTokens not set to Prod"


def test_analyze_apache_config_reports_missing_trace_enable(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            [
                "ServerSignature Off",
                "ServerTokens Prod",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                '<FilesMatch "\\.(bak|old|backup|orig|save|swp|tmp)$">',
                "    Require all denied",
                "</FilesMatch>",
                *_SAFE_APACHE_CIS_BASELINE_LINES,
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.trace_enable_not_off"
    assert finding.title == "TraceEnable not set to Off"


def test_analyze_apache_config_does_not_report_trace_enable_when_off(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "ServerTokens Prod\n"
            "TraceEnable Off\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_unsafe_trace_enable(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "ServerTokens Prod\n"
            "TraceEnable On\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.trace_enable_not_off"
    assert finding.title == "TraceEnable not set to Off"


def test_analyze_apache_config_reports_trace_enable_location_for_explicit_bad_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "ServerTokens Prod\n"
            "TraceEnable On\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.trace_enable_not_off"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 3
