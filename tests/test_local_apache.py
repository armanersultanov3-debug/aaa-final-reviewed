from pathlib import Path

import pytest

from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.apache.effective import (
    build_effective_config,
    build_server_effective_config,
    extract_virtualhost_contexts,
    select_applicable_virtualhosts,
)
from webconf_audit.local.apache.htaccess import (
    ALL_OVERRIDE_CATEGORIES,
    HtaccessFile,
    discover_htaccess_files,
    extract_allowoverride,
    filter_htaccess_by_allowoverride,
)
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheParseError, parse_apache_config
from webconf_audit.local.apache.rules.context_sensitive_directive_utils import (
    find_context_sensitive_directives,
)
from webconf_audit.local.apache.rules.htaccess_weakens_security import (
    find_htaccess_weakens_security,
)

_SAFE_SECURITY_HEADER_LINES = {
    "x-content-type-options": "Header set X-Content-Type-Options nosniff",
    "x-frame-options": "Header set X-Frame-Options SAMEORIGIN",
    "content-security-policy": (
        "Header set Content-Security-Policy "
        "\"default-src 'self'; frame-ancestors 'self'\""
    ),
    "referrer-policy": "Header set Referrer-Policy strict-origin-when-cross-origin",
    "permissions-policy": (
        'Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"'
    ),
}
_SAFE_SECURITY_HEADER_ALWAYS_LINES = {
    header: line.replace("Header set ", "Header always set ", 1)
    for header, line in _SAFE_SECURITY_HEADER_LINES.items()
}
_SAFE_SECURITY_HEADER_BASELINE_LINES = [
    line
    for header in _SAFE_SECURITY_HEADER_LINES
    for line in (
        _SAFE_SECURITY_HEADER_LINES[header],
        _SAFE_SECURITY_HEADER_ALWAYS_LINES[header],
    )
]


def _with_backup_files_restriction(
    config_text: str,
    *,
    include_security_headers: bool = True,
) -> str:
    security_headers = (
        "\n" + "\n".join(_SAFE_SECURITY_HEADER_BASELINE_LINES)
        if include_security_headers
        else ""
    )
    return config_text.rstrip("\n") + security_headers + (
        '\n<FilesMatch "\\.(bak|old|swp)$">\n'
        "    Require all denied\n"
        "</FilesMatch>"
    )


def _safe_apache_config(*extra_lines: str) -> str:
    lines = [
        "ServerSignature Off",
        "TraceEnable Off",
        "ServerTokens Prod",
        "LimitRequestBody 102400",
        "LimitRequestFields 100",
        "ErrorLog logs/error_log",
        "CustomLog logs/access_log combined",
        "ErrorDocument 404 /custom404.html",
        "ErrorDocument 500 /custom500.html",
        "Listen 80",
    ]
    lines.extend(extra_lines)
    return _with_backup_files_restriction("\n".join(lines))


def _safe_apache_config_without_headers(
    *extra_lines: str,
    omit_headers: set[str] | None = None,
) -> str:
    omit = {header.lower() for header in omit_headers or set()}
    base_lines = _safe_apache_config().splitlines()
    omitted_lines = set()
    for header in omit:
        omitted_lines.update(
            line
            for line in (
                _SAFE_SECURITY_HEADER_LINES.get(header),
                _SAFE_SECURITY_HEADER_ALWAYS_LINES.get(header),
            )
            if line is not None and line in base_lines
        )
    filtered_lines = [line for line in base_lines if line not in omitted_lines]
    for extra_line in extra_lines:
        filtered_lines.extend(extra_line.splitlines())
    return "\n".join(filtered_lines)


def _safe_apache_config_with_late_lines(*extra_lines: str) -> str:
    config = _safe_apache_config()
    marker = '\n<FilesMatch "\\.(bak|old|swp)$">'
    if marker not in config:
        raise AssertionError(
            "_safe_apache_config_with_late_lines: expected backup-files marker "
            f"{marker!r} to be present in the safe base config so that late "
            "lines can be inserted before the FilesMatch block."
        )
    return config.replace(marker, "\n" + "\n".join(extra_lines) + marker, 1)


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


def _analyze_with_htaccess(
    tmp_path: Path,
    htaccess_text: str,
    *,
    allowoverride: str | None = "All",
    config_prefix: str = "",
    config_suffix: str = "",
):
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".htaccess").write_text(htaccess_text, encoding="utf-8")

    directory_lines = [f'<Directory "{_posix_path(web_dir)}">']
    if allowoverride is not None:
        directory_lines.append(f"    AllowOverride {allowoverride}")
    directory_lines.append("</Directory>")

    config_parts = [
        config_prefix.rstrip("\n"),
        "\n".join(directory_lines),
        "ServerSignature Off",
        "ServerTokens Prod",
        "TraceEnable Off",
        "LimitRequestBody 102400",
        "LimitRequestFields 100",
        "ErrorLog logs/error_log",
        "CustomLog logs/access_log combined",
        'ErrorDocument 404 "/error/404.html"',
        'ErrorDocument 500 "/error/500.html"',
        config_suffix.rstrip("\n"),
    ]

    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction("\n".join(part for part in config_parts if part)),
        encoding="utf-8",
    )
    return analyze_apache_config(str(config_path)), web_dir


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
                    "Listen 80",
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
                '<FilesMatch "\\.(bak|old|swp)$">',
                "    Require all denied",
                "</FilesMatch>",
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
                "Listen 80",
                *_SAFE_SECURITY_HEADER_BASELINE_LINES,
                "<VirtualHost *:80>",
                "    ServerName example.test",
                '    <Directory "/var/www/html">',
                "        AllowOverride None",
                "        Options -Indexes",
                '        <FilesMatch "\\.(bak|old|swp)$">',
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
                '<FilesMatch "\\.(bak|old|swp)$">',
                "    Require all denied",
                "</FilesMatch>",
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
            '<FilesMatch "\\.(bak|old|swp)$">',
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
                '<FilesMatch "\\.(bak|old|swp)$">',
                "    Require all granted",
                "</FilesMatch>",
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
                    "Listen 80",
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
            "Listen 80\n"
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
            "Listen 80\n"
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
            "Listen 80\n"
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
                '<FilesMatch "\\.(bak|old|swp)$">',
                "    Require all denied",
                "</FilesMatch>",
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


def test_analyze_apache_config_does_not_report_options_indexes_when_disabled(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options -Indexes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_options_indexes_in_directory(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Indexes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_indexes"
    assert finding.title == "Directory indexing enabled"


def test_analyze_apache_config_reports_mixed_options_indexes_in_directory(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options FollowSymLinks Indexes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_indexes"
    assert finding.title == "Directory indexing enabled"


def test_analyze_apache_config_reports_options_plus_execcgi_in_directory(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html/cgi-bin">',
                    "    AllowOverride None",
                    "    Options +ExecCGI",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_execcgi_enabled"
    assert finding.title == "ExecCGI enabled via Options"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 12


def test_analyze_apache_config_reports_options_execcgi_in_directory(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html/cgi-bin">',
                    "    AllowOverride None",
                    "    Options ExecCGI",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_execcgi_enabled"
    assert finding.title == "ExecCGI enabled via Options"


def test_analyze_apache_config_reports_options_execcgi_in_virtual_host(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "<VirtualHost *:80>",
                    "    Options Indexes ExecCGI",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    execcgi_findings = [
        f for f in result.findings if f.rule_id == "apache.options_execcgi_enabled"
    ]
    assert len(execcgi_findings) == 1
    finding = execcgi_findings[0]
    assert finding.title == "ExecCGI enabled via Options"
    assert finding.location is not None
    assert finding.location.line == 11


def test_analyze_apache_config_does_not_report_options_execcgi_when_absent(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html/cgi-bin">',
                    "    AllowOverride None",
                    "    Require all granted",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_does_not_report_safe_options_without_execcgi(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "<VirtualHost *:80>",
                    "    Options FollowSymLinks SymLinksIfOwnerMatch",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    apache_findings = [f for f in result.findings if f.rule_id.startswith("apache.")]
    assert apache_findings == []


def test_analyze_apache_config_does_not_report_options_minus_execcgi_in_directory(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html/cgi-bin">',
                    "    AllowOverride None",
                    "    Options -ExecCGI",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_does_not_report_options_includes_when_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options FollowSymLinks SymLinksIfOwnerMatch",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_options_indexes_includes_in_directory(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Indexes Includes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    includes_findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.options_includes_enabled"
    ]

    assert result.issues == []
    assert len(includes_findings) == 1
    assert includes_findings[0].title == "Includes enabled via Options"


def test_analyze_apache_config_reports_options_includes_in_directory(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Includes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_includes_enabled"
    assert finding.title == "Includes enabled via Options"


def test_analyze_apache_config_reports_options_includes_in_virtual_host(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "<VirtualHost *:80>",
                    "    Options Includes",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [f for f in result.findings if f.rule_id == "apache.options_includes_enabled"]
    assert len(matching) == 1
    finding = matching[0]
    assert finding.rule_id == "apache.options_includes_enabled"
    assert finding.title == "Includes enabled via Options"


def test_analyze_apache_config_reports_options_includes_location(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Includes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_includes_enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 12


def test_analyze_apache_config_does_not_report_options_multiviews_when_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options FollowSymLinks SymLinksIfOwnerMatch",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_options_multiviews_in_directory(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options MultiViews",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_multiviews_enabled"
    assert finding.title == "MultiViews enabled via Options"


def test_analyze_apache_config_reports_options_indexes_multiviews_in_directory(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Indexes MultiViews",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    multiviews_findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.options_multiviews_enabled"
    ]

    assert result.issues == []
    assert len(multiviews_findings) == 1
    assert multiviews_findings[0].title == "MultiViews enabled via Options"


def test_analyze_apache_config_reports_options_multiviews_in_virtual_host(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "<VirtualHost *:80>",
                    "    Options MultiViews",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [f for f in result.findings if f.rule_id == "apache.options_multiviews_enabled"]
    assert len(matching) == 1
    finding = matching[0]
    assert finding.rule_id == "apache.options_multiviews_enabled"
    assert finding.title == "MultiViews enabled via Options"


def test_analyze_apache_config_does_not_report_options_minus_multiviews_in_directory(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options -MultiViews",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_options_multiviews_location(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options MultiViews",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_multiviews_enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 12


def test_analyze_apache_config_does_not_report_index_options_risky_tokens_when_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions NameWidth=* DescriptionWidth=*",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_index_options_fancyindexing_in_directory(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions FancyIndexing",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.index_options_fancyindexing_enabled"
    assert finding.title == "FancyIndexing enabled via IndexOptions"


def test_analyze_apache_config_reports_index_options_scanhtmltitles_in_directory(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions ScanHTMLTitles",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.index_options_scanhtmltitles_enabled"
    assert finding.title == "ScanHTMLTitles enabled via IndexOptions"


def test_analyze_apache_config_reports_index_options_fancyindexing_in_virtual_host(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "<VirtualHost *:80>",
                    "    IndexOptions FancyIndexing",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [f for f in result.findings if f.rule_id == "apache.index_options_fancyindexing_enabled"]
    assert len(matching) == 1
    finding = matching[0]
    assert finding.rule_id == "apache.index_options_fancyindexing_enabled"
    assert finding.title == "FancyIndexing enabled via IndexOptions"


def test_analyze_apache_config_reports_index_options_scanhtmltitles_in_virtual_host(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "<VirtualHost *:80>",
                    "    IndexOptions ScanHTMLTitles",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [f for f in result.findings if f.rule_id == "apache.index_options_scanhtmltitles_enabled"]
    assert len(matching) == 1
    finding = matching[0]
    assert finding.rule_id == "apache.index_options_scanhtmltitles_enabled"
    assert finding.title == "ScanHTMLTitles enabled via IndexOptions"


def test_analyze_apache_config_does_not_report_index_options_minus_fancyindexing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions -FancyIndexing",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_does_not_report_index_options_minus_scanhtmltitles(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions -ScanHTMLTitles",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_both_index_options_findings_with_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions FancyIndexing ScanHTMLTitles",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    findings_by_rule_id = {finding.rule_id: finding for finding in result.findings}

    assert result.issues == []
    assert len(result.findings) == 2
    assert set(findings_by_rule_id) == {
        "apache.index_options_fancyindexing_enabled",
        "apache.index_options_scanhtmltitles_enabled",
    }
    assert (
        findings_by_rule_id["apache.index_options_fancyindexing_enabled"].location is not None
    )
    assert (
        findings_by_rule_id["apache.index_options_scanhtmltitles_enabled"].location is not None
    )
    assert (
        findings_by_rule_id["apache.index_options_fancyindexing_enabled"].location.file_path
        == str(config_path)
    )
    assert (
        findings_by_rule_id["apache.index_options_scanhtmltitles_enabled"].location.file_path
        == str(config_path)
    )
    assert findings_by_rule_id["apache.index_options_fancyindexing_enabled"].location.line == 12
    assert findings_by_rule_id["apache.index_options_scanhtmltitles_enabled"].location.line == 12


def test_analyze_apache_config_does_not_report_server_status_when_require_ip_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Location "/server-status">',
                    "    SetHandler server-status",
                    "    Require ip 192.168.0.0/24",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_exposed_server_status_without_require_ip(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Location "/server-status">',
                    "    SetHandler server-status",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.server_status_exposed"
    assert finding.title == "server-status endpoint exposed"


def test_analyze_apache_config_respects_virtualhost_location_override_for_server_status(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Location "/server-status">',
                    "    SetHandler server-status",
                    "</Location>",
                    "<VirtualHost *:80>",
                    "    ServerName secure.example.test",
                    '    DocumentRoot "/var/www/secure"',
                    '    <Location "/server-status">',
                    "        Require ip 127.0.0.1",
                    "    </Location>",
                    "</VirtualHost>",
                    "<VirtualHost *:80>",
                    "    ServerName insecure.example.test",
                    '    DocumentRoot "/var/www/insecure"',
                    '    <Location "/server-status">',
                    "        SetHandler server-status",
                    "    </Location>",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.server_status_exposed"
    ]

    assert result.issues == []
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(config_path)
    assert findings[0].location.line == 23


def test_analyze_apache_config_does_not_report_server_info_when_require_ip_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Location "/server-info">',
                    "    SetHandler server-info",
                    "    Require ip 127.0.0.1",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_exposed_server_info_without_require_ip(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Location "/server-info">',
                    "    SetHandler server-info",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.server_info_exposed"
    assert finding.title == "server-info endpoint exposed"


def test_analyze_apache_config_respects_virtualhost_location_override_for_server_info(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Location "/server-info">',
                    "    SetHandler server-info",
                    "</Location>",
                    "<VirtualHost *:80>",
                    "    ServerName secure.example.test",
                    '    DocumentRoot "/var/www/secure"',
                    '    <Location "/server-info">',
                    "        Require ip 127.0.0.1",
                    "    </Location>",
                    "</VirtualHost>",
                    "<VirtualHost *:80>",
                    "    ServerName insecure.example.test",
                    '    DocumentRoot "/var/www/insecure"',
                    '    <Location "/server-info">',
                    "        SetHandler server-info",
                    "    </Location>",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.server_info_exposed"
    ]

    assert result.issues == []
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(config_path)
    assert findings[0].location.line == 23


def test_analyze_apache_config_does_not_report_limit_request_body_when_positive_integer(
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
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert server_findings == []


def test_analyze_apache_config_reports_missing_limit_request_body(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.limit_request_body_missing_or_invalid"
    assert finding.title == "LimitRequestBody not configured safely"


def test_analyze_apache_config_reports_missing_limit_request_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.limit_request_fields_missing_or_invalid"
    assert finding.title == "LimitRequestFields not configured safely"


def test_analyze_apache_config_does_not_report_limit_request_fields_when_positive_integer(
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
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert server_findings == []


def test_analyze_apache_config_reports_zero_limit_request_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 0\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.limit_request_fields_missing_or_invalid"
    assert finding.title == "LimitRequestFields not configured safely"


def test_analyze_apache_config_reports_invalid_limit_request_fields_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields abc\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.limit_request_fields_missing_or_invalid"
    assert finding.title == "LimitRequestFields not configured safely"


def test_analyze_apache_config_reports_limit_request_fields_location_for_bad_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields abc\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.limit_request_fields_missing_or_invalid"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 5


def test_analyze_apache_config_reports_invalid_limit_request_body_value(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody unlimited\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.limit_request_body_missing_or_invalid"
    assert finding.title == "LimitRequestBody not configured safely"


def test_analyze_apache_config_reports_zero_limit_request_body(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "ServerSignature Off\n"
            "TraceEnable Off\n"
            "ServerTokens Prod\n"
            "LimitRequestBody 0\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            "ErrorDocument 404 /custom404.html\n"
            "ErrorDocument 500 /custom500.html\n"
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.limit_request_body_missing_or_invalid"
    assert finding.title == "LimitRequestBody not configured safely"


def test_analyze_apache_config_accepts_cis_safe_apache_policy_values(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            "FileETag MTime Size",
            "Timeout 10",
            "KeepAlive On",
            "MaxKeepAliveRequests 100",
            "KeepAliveTimeout 15",
            "LimitRequestLine 8190",
            "LimitRequestFieldSize 8190",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert server_findings == []


@pytest.mark.parametrize(
    ("bad_directive", "rule_id"),
    [
        ("FileETag All", "apache.file_etag_inodes"),
        ("FileETag MTime +INode Size", "apache.file_etag_inodes"),
        ("Timeout 60", "apache.timeout_too_high"),
        ("KeepAlive Off", "apache.keepalive_disabled"),
        ("MaxKeepAliveRequests 0", "apache.max_keepalive_requests_too_low"),
        ("MaxKeepAliveRequests 50", "apache.max_keepalive_requests_too_low"),
        ("KeepAliveTimeout 20", "apache.keepalive_timeout_too_high"),
        ("LimitRequestLine 8191", "apache.limit_request_line_too_high"),
        ("LimitRequestFieldSize 8191", "apache.limit_request_field_size_too_high"),
        ("LimitRequestBody 102401", "apache.limit_request_body_missing_or_invalid"),
        ("LimitRequestFields 101", "apache.limit_request_fields_missing_or_invalid"),
    ],
)
def test_analyze_apache_config_reports_cis_apache_policy_value_findings(
    tmp_path: Path,
    bad_directive: str,
    rule_id: str,
) -> None:
    config_path = tmp_path / "httpd.conf"
    baseline_lines = [
        "FileETag MTime Size",
        "Timeout 10",
        "KeepAlive On",
        "MaxKeepAliveRequests 100",
        "KeepAliveTimeout 15",
        "LimitRequestLine 8190",
        "LimitRequestFieldSize 8190",
    ]
    directive_name = bad_directive.split()[0].lower()
    config_path.write_text(
        _safe_apache_config(
            *[
                line
                for line in baseline_lines
                if line.split()[0].lower() != directive_name
            ],
            bad_directive,
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    apache_findings = [
        finding
        for finding in result.findings
        if finding.rule_id.startswith("apache.")
    ]
    assert len(apache_findings) == 1
    assert apache_findings[0].rule_id == rule_id
    assert apache_findings[0].location is not None
    assert apache_findings[0].location.file_path == str(config_path)


def test_analyze_apache_config_uses_effective_file_etag_value(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            "FileETag All",
            "FileETag MTime Size",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(f.rule_id == "apache.file_etag_inodes" for f in result.findings)


def test_analyze_apache_config_reports_final_unsafe_file_etag_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            "FileETag MTime Size",
            "FileETag All",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    findings = [f for f in result.findings if f.rule_id == "apache.file_etag_inodes"]
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(config_path)


@pytest.mark.parametrize(
    ("header_name", "rule_id"),
    [
        ("x-frame-options", "apache.missing_x_frame_options_header"),
        ("referrer-policy", "apache.missing_referrer_policy_header"),
        ("permissions-policy", "apache.missing_permissions_policy_header"),
    ],
)
def test_analyze_apache_config_reports_missing_security_header_policy(
    tmp_path: Path,
    header_name: str,
    rule_id: str,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(omit_headers={header_name}),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    apache_findings = [
        finding
        for finding in result.findings
        if finding.rule_id.startswith("apache.")
    ]
    assert len(apache_findings) == 1
    assert apache_findings[0].rule_id == rule_id
    assert apache_findings[0].location is not None
    assert apache_findings[0].location.file_path == str(config_path)


def test_safe_apache_config_without_headers_preserves_matching_override(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            _SAFE_SECURITY_HEADER_LINES["x-frame-options"],
            _SAFE_SECURITY_HEADER_ALWAYS_LINES["x-frame-options"],
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
        for finding in result.findings
    )


@pytest.mark.parametrize(
    ("header_line", "rule_id"),
    [
        (
            "Header set X-Frame-Options ALLOW-FROM https://legacy.example.test",
            "apache.x_frame_options_unsafe",
        ),
        ("Header set Referrer-Policy unsafe-url", "apache.referrer_policy_unsafe"),
        (
            'Header set Permissions-Policy "geolocation=*, microphone=()"',
            "apache.permissions_policy_unsafe",
        ),
    ],
)
def test_analyze_apache_config_reports_unsafe_security_header_policy(
    tmp_path: Path,
    header_line: str,
    rule_id: str,
) -> None:
    header_name = header_line.split()[2].lower()
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            header_line,
            _SAFE_SECURITY_HEADER_ALWAYS_LINES[header_name],
            omit_headers={header_name},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    apache_findings = [
        finding
        for finding in result.findings
        if finding.rule_id.startswith("apache.")
    ]
    assert len(apache_findings) == 1
    assert apache_findings[0].rule_id == rule_id
    assert apache_findings[0].location is not None
    assert apache_findings[0].location.file_path == str(config_path)


def test_analyze_apache_config_treats_dynamic_security_header_value_as_unknown(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header always set X-Frame-Options expr=%{REQUEST_STATUS}",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
    ]
    assert result.issues == []
    assert matching == []


def test_analyze_apache_config_treats_trailing_expr_as_header_condition(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header always set X-Frame-Options DENY expr=%{REQUEST_STATUS}",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
    ]
    assert result.issues == []
    assert [finding.rule_id for finding in matching] == [
        "apache.missing_x_frame_options_header"
    ]


def test_analyze_apache_config_flags_static_unsafe_header_with_runtime_condition(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header always set X-Frame-Options "
            "ALLOW-FROM https://legacy.example.test env=legacy",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
    ]
    assert result.issues == []
    assert {finding.rule_id for finding in matching} == {
        "apache.missing_x_frame_options_header",
        "apache.x_frame_options_unsafe",
    }
    assert all(finding.location is not None for finding in matching)
    assert {finding.location.file_path for finding in matching if finding.location} == {
        str(config_path)
    }


@pytest.mark.parametrize(
    ("header_line", "rule_id"),
    [
        ("Header setifempty X-Frame-Options SAMEORIGIN", None),
        (
            "Header setifempty X-Frame-Options "
            "ALLOW-FROM https://legacy.example.test",
            "apache.x_frame_options_unsafe",
        ),
        ("Header add X-Frame-Options DENY", None),
        (
            "Header add X-Frame-Options ALLOW-FROM https://legacy.example.test",
            "apache.x_frame_options_unsafe",
        ),
        ("Header append X-Frame-Options SAMEORIGIN", None),
        (
            "Header append X-Frame-Options ALLOW-FROM https://legacy.example.test",
            "apache.x_frame_options_unsafe",
        ),
        ("Header merge X-Frame-Options DENY", None),
        (
            "Header merge X-Frame-Options ALLOW-FROM https://legacy.example.test",
            "apache.x_frame_options_unsafe",
        ),
    ],
)
def test_analyze_apache_config_supports_security_header_actions(
    tmp_path: Path,
    header_line: str,
    rule_id: str | None,
) -> None:
    always_value = (
        "DENY"
        if rule_id is not None
        else header_line.split("X-Frame-Options ", 1)[1]
    )
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            header_line,
            f"Header always set X-Frame-Options {always_value}",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
    ]
    assert result.issues == []
    if rule_id is None:
        assert matching == []
    else:
        assert len(matching) == 1
        assert matching[0].rule_id == rule_id
        assert matching[0].location is not None
        assert matching[0].location.file_path == str(config_path)


def test_analyze_apache_config_honors_virtualhost_security_header_override(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            "<VirtualHost *:80>",
            "    ServerName safe.test",
            "    Header unset X-Frame-Options",
            "    Header always set X-Frame-Options DENY",
            "    Header onsuccess set X-Frame-Options DENY",
            "</VirtualHost>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
        for finding in result.findings
    )


def test_analyze_apache_config_keeps_header_conditions_separate(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header always set X-Frame-Options DENY",
            "Header onsuccess unset X-Frame-Options",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
    ]
    assert result.issues == []
    assert matching == []


def test_analyze_apache_config_reports_missing_for_onsuccess_only_security_header(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header set X-Frame-Options DENY",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
    ]
    assert result.issues == []
    assert len(matching) == 1
    assert matching[0].rule_id == "apache.missing_x_frame_options_header"


def test_analyze_apache_config_reports_missing_for_non_exhaustive_header_wrapper(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "<IfModule mod_headers.c>",
            "    Header always set X-Frame-Options DENY",
            "</IfModule>",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.missing_x_frame_options_header"
    ]
    assert result.issues == []
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.file_path == str(config_path)


def test_analyze_apache_config_treats_valid_else_if_header_chain_as_exhaustive(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "<If \"%{HTTP_HOST} == 'primary.test'\">",
            "    Header always set X-Frame-Options DENY",
            "</If>",
            "<ElseIf \"%{HTTP_HOST} == 'legacy.test'\">",
            "    Header always set X-Frame-Options SAMEORIGIN",
            "</ElseIf>",
            "<Else>",
            "    Header always set X-Frame-Options DENY",
            "</Else>",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
    ]
    assert result.issues == []
    assert matching == []


def test_analyze_apache_config_reports_conditional_missing_security_header(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "<If \"%{HTTP_HOST} == 'no-header.test'\">",
            "    Header unset X-Frame-Options",
            "    Header always unset X-Frame-Options",
            "</If>",
            "<Else>",
            "    Header set X-Frame-Options SAMEORIGIN",
            "    Header always set X-Frame-Options SAMEORIGIN",
            "</Else>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.missing_x_frame_options_header"
    ]
    assert result.issues == []
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.file_path == str(config_path)


def test_analyze_apache_config_treats_if_else_header_chain_as_exhaustive(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "<If \"%{HTTP_HOST} == 'primary.test'\">",
            "    Header set X-Frame-Options DENY",
            "    Header always set X-Frame-Options DENY",
            "</If>",
            "<Else>",
            "    Header set X-Frame-Options SAMEORIGIN",
            "    Header always set X-Frame-Options SAMEORIGIN",
            "</Else>",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
        for finding in result.findings
    )


def test_analyze_apache_config_reports_conditional_unsafe_security_header(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_with_late_lines(
            "<IfModule mod_headers.c>",
            "    Header set Referrer-Policy unsafe-url",
            "</IfModule>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.referrer_policy_unsafe"
    ]
    assert result.issues == []
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.file_path == str(config_path)


def test_analyze_apache_config_flags_combined_unsafe_security_header_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header always set X-Frame-Options DENY",
            "Header always append X-Frame-Options SAMEORIGIN",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.x_frame_options_unsafe"
    ]
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.file_path == str(config_path)


def test_analyze_apache_config_flags_add_multi_instance_unsafe_security_header(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    add_directive = "Header add X-Frame-Options SAMEORIGIN"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header set X-Frame-Options DENY",
            add_directive,
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.x_frame_options_unsafe"
    ]
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.file_path == str(config_path)
    config_lines = config_path.read_text(encoding="utf-8").splitlines()
    expected_line = config_lines.index(add_directive) + 1
    assert matching[0].location.line == expected_line


def test_analyze_apache_config_flags_merge_combined_unsafe_security_header_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header always set Referrer-Policy strict-origin-when-cross-origin",
            "Header always merge Referrer-Policy unsafe-url",
            omit_headers={"referrer-policy"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.referrer_policy_unsafe"
    ]
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.file_path == str(config_path)


def test_analyze_apache_config_skips_security_headers_when_no_listen(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "ServerSignature Off\nServerTokens Prod\nTraceEnable Off\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.missing_referrer_policy_header",
            "apache.missing_permissions_policy_header",
        }
        for finding in result.findings
    )


def test_analyze_apache_config_skips_inactive_virtualhost_security_headers(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "ServerSignature Off\nServerTokens Prod\nTraceEnable Off\n"
        "<VirtualHost *:443>\n"
        "    ServerName inactive.test\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.missing_referrer_policy_header",
            "apache.missing_permissions_policy_header",
        }
        for finding in result.findings
    )


def test_analyze_apache_config_skips_conditional_virtualhost_security_header_scope(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            "<IfModule mod_optional_vhost.c>",
            "    <VirtualHost *:80>",
            "        ServerName optional.test",
            "        Header always unset X-Frame-Options",
            "    </VirtualHost>",
            "</IfModule>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
        and finding.metadata.get("scope_name") == "optional.test"
    ]
    assert result.issues == []
    assert matching == []


def test_analyze_apache_config_skips_unsafe_for_inactive_virtualhost_inheriting_global(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "ServerSignature Off\n"
        "ServerTokens Prod\n"
        "TraceEnable Off\n"
        "Header set X-Frame-Options ALLOW-FROM https://legacy.example.test\n"
        "<VirtualHost *:443>\n"
        "    ServerName inactive.test\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.x_frame_options_unsafe"
    ]
    assert len(matching) == 1
    assert matching[0].metadata.get("scope_name") == "global"


def test_analyze_apache_config_blames_last_applied_directive_for_combined_unsafe(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    onsuccess_directive = "Header onsuccess set X-Frame-Options DENY"
    always_directive = "Header always set X-Frame-Options SAMEORIGIN"
    config_path.write_text(
        _safe_apache_config_without_headers(
            onsuccess_directive,
            always_directive,
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.x_frame_options_unsafe"
    ]
    assert len(matching) == 1
    config_lines = config_path.read_text(encoding="utf-8").splitlines()
    expected_line = config_lines.index(always_directive) + 1
    assert matching[0].location is not None
    assert matching[0].location.line == expected_line


def test_analyze_apache_config_preserves_include_apply_order_for_header_blame(
    tmp_path: Path,
) -> None:
    included_path = tmp_path / "included-headers.conf"
    included_path.write_text(
        "Header always set X-Frame-Options SAMEORIGIN\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header onsuccess set X-Frame-Options DENY",
            f'Include "{_posix_path(included_path)}"',
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.x_frame_options_unsafe"
    ]
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.file_path == str(included_path)
    assert matching[0].location.line == 1


def test_analyze_apache_config_handles_many_independent_optional_blocks(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    optional_blocks = []
    for index in range(12):
        optional_blocks.extend(
            [
                f"<IfModule mod_extra_{index}.c>",
                f"    SetEnv WEBCONF_AUDIT_FLAG_{index} on",
                "</IfModule>",
            ]
        )
    config_path.write_text(
        _safe_apache_config(*optional_blocks),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
            "apache.missing_referrer_policy_header",
            "apache.referrer_policy_unsafe",
            "apache.missing_permissions_policy_header",
        }
        for finding in result.findings
    )


def test_analyze_apache_config_treats_if_else_branches_as_alternatives(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "<If \"%{HTTP_HOST} == 'a.test'\">",
            "    Header set X-Frame-Options DENY",
            "    Header always set X-Frame-Options DENY",
            "</If>",
            "<Else>",
            "    Header set X-Frame-Options SAMEORIGIN",
            "    Header always set X-Frame-Options SAMEORIGIN",
            "</Else>",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
        for finding in result.findings
    )


def test_analyze_apache_config_flags_unsafe_if_branch_when_other_is_safe(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "<If \"%{HTTP_HOST} == 'legacy.test'\">",
            "    Header always set X-Frame-Options ALLOW-FROM https://legacy.example.test",
            "</If>",
            "<Else>",
            "    Header always set X-Frame-Options DENY",
            "</Else>",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.x_frame_options_unsafe"
    ]
    assert len(matching) == 1
    assert not any(
        finding.rule_id == "apache.missing_x_frame_options_header"
        for finding in result.findings
    )


def test_analyze_apache_config_accepts_permissions_policy_with_comma_allowlist(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            'Header always set Permissions-Policy "geolocation=(self, https://example.test)"',
            omit_headers={"permissions-policy"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.missing_permissions_policy_header",
            "apache.permissions_policy_unsafe",
        }
        for finding in result.findings
    )


def test_analyze_apache_config_skips_global_headers_when_listen_is_covered(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "<VirtualHost *:80>",
            "    ServerName covered.test",
            "    Header set X-Frame-Options DENY",
            "    Header always set X-Frame-Options DENY",
            "</VirtualHost>",
            omit_headers=set(_SAFE_SECURITY_HEADER_LINES),
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
        and finding.metadata.get("scope_name") == "global"
        for finding in result.findings
    )


def test_analyze_apache_config_flags_always_onsuccess_multi_instance_unsafe(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header always set X-Frame-Options DENY",
            "Header onsuccess set X-Frame-Options SAMEORIGIN",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.x_frame_options_unsafe"
    ]
    assert len(matching) == 1


def test_analyze_apache_config_audits_global_scope_when_virtualhosts_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header set X-Frame-Options ALLOW-FROM https://legacy.example.test",
            "<VirtualHost *:80>",
            "    ServerName covered.test",
            "    Header unset X-Frame-Options",
            "    Header set X-Frame-Options DENY",
            "</VirtualHost>",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.x_frame_options_unsafe"
    ]
    assert len(matching) == 1
    assert matching[0].metadata.get("scope_name") == "global"


def test_analyze_apache_config_accepts_referrer_policy_fallback_chain(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header set Referrer-Policy strict-origin-when-cross-origin",
            "Header always set Referrer-Policy strict-origin-when-cross-origin",
            "Header merge Referrer-Policy no-referrer",
            omit_headers={"referrer-policy"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.missing_referrer_policy_header",
            "apache.referrer_policy_unsafe",
        }
        for finding in result.findings
    )


def test_analyze_apache_config_recognizes_virtualhost_with_multiple_bind_addresses(
    tmp_path: Path,
) -> None:
    safe_vh_headers = (
        "    Header always set X-Frame-Options DENY",
        "    Header always set X-Content-Type-Options nosniff",
        '    Header always set Content-Security-Policy '
        '"default-src \'self\'; frame-ancestors \'self\'"',
        "    Header always set Referrer-Policy strict-origin-when-cross-origin",
        '    Header always set Permissions-Policy '
        '"geolocation=(), microphone=(), camera=()"',
    )
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            (
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "Listen 80",
                "Listen 443",
                "<VirtualHost *:80 *:443>",
                "    ServerName covered.test",
                *safe_vh_headers,
                "</VirtualHost>",
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    security_header_rules = {
        "apache.missing_x_frame_options_header",
        "apache.missing_referrer_policy_header",
        "apache.missing_permissions_policy_header",
        "apache.x_frame_options_unsafe",
        "apache.referrer_policy_unsafe",
    }
    assert not any(
        finding.rule_id in security_header_rules
        and finding.metadata.get("scope_name") == "global"
        for finding in result.findings
    )


def test_analyze_apache_config_ignores_conditional_listen_when_checking_coverage(
    tmp_path: Path,
) -> None:
    safe_vh_headers = (
        "    Header always set X-Frame-Options DENY",
        "    Header always set X-Content-Type-Options nosniff",
        '    Header always set Content-Security-Policy '
        '"default-src \'self\'; frame-ancestors \'self\'"',
        "    Header always set Referrer-Policy strict-origin-when-cross-origin",
        '    Header always set Permissions-Policy '
        '"geolocation=(), microphone=(), camera=()"',
    )
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            (
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "Listen 80",
                "<IfDefine ENABLE_TLS>",
                "    Listen 443",
                "</IfDefine>",
                "<VirtualHost *:80>",
                "    ServerName covered.test",
                *safe_vh_headers,
                "</VirtualHost>",
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    security_header_rules = {
        "apache.missing_x_frame_options_header",
        "apache.missing_referrer_policy_header",
        "apache.missing_permissions_policy_header",
    }
    assert not any(
        finding.rule_id in security_header_rules
        and finding.metadata.get("scope_name") == "global"
        for finding in result.findings
    )


def test_analyze_apache_config_accepts_referrer_policy_with_unknown_trailing_token(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            'Header always set Referrer-Policy "strict-origin-when-cross-origin, future-policy"',
            omit_headers={"referrer-policy"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id
        in {
            "apache.referrer_policy_unsafe",
            "apache.missing_referrer_policy_header",
        }
        for finding in result.findings
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
            "Listen 80\n"
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
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.error_log_missing"
    assert finding.title == "Missing top-level ErrorLog directive"


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
            "Listen 80\n"
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1
    finding = server_findings[0]
    assert finding.rule_id == "apache.custom_log_missing"
    assert finding.title == "Missing top-level CustomLog directive"


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
            "Listen 80\n"
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
            "Listen 80\n"
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
            "Listen 80\n"
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
            "Listen 80\n"
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
            "Listen 80\n"
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

def _posix_path(p: Path) -> str:
    """Return forward-slash path string safe for embedding in Apache config text."""
    return str(p).replace("\\", "/")


def test_htaccess_discovered_for_directory_block(tmp_path: Path) -> None:
    web_dir = tmp_path / "var" / "www"
    web_dir.mkdir(parents=True)
    (web_dir / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert Path(result.found[0].directory_path).resolve() == web_dir.resolve()
    assert Path(result.found[0].htaccess_path).resolve() == (web_dir / ".htaccess").resolve()
    assert result.found[0].source_directory_block is not None
    assert result.found[0].ast.nodes[0].name == "Options"
    assert result.issues == []


def test_htaccess_not_found_no_error(tmp_path: Path) -> None:
    web_dir = tmp_path / "var" / "www"
    web_dir.mkdir(parents=True)

    config = parse_apache_config(
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert result.found == []
    assert result.issues == []


def test_htaccess_parse_error_produces_issue(tmp_path: Path) -> None:
    web_dir = tmp_path / "var" / "www"
    web_dir.mkdir(parents=True)
    (web_dir / ".htaccess").write_text(
        "<IfModule mod_rewrite.c>\n",  # unterminated block
        encoding="utf-8",
    )

    config = parse_apache_config(
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert result.found == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "htaccess_parse_error"


def test_htaccess_multiple_directories(tmp_path: Path) -> None:
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")
    (dir_b / ".htaccess").write_text("Options +FollowSymLinks\n", encoding="utf-8")

    config = parse_apache_config(
        f'<Directory "{_posix_path(dir_a)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
        f'<Directory "{_posix_path(dir_b)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 2
    resolved_paths = {Path(hf.directory_path).resolve() for hf in result.found}
    assert dir_a.resolve() in resolved_paths
    assert dir_b.resolve() in resolved_paths


def test_htaccess_custom_access_file_name(tmp_path: Path) -> None:
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".override").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        "AccessFileName .override\n"
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert Path(result.found[0].htaccess_path).resolve() == (web_dir / ".override").resolve()


def test_htaccess_document_root_is_checked(tmp_path: Path) -> None:
    doc_root = tmp_path / "htdocs"
    doc_root.mkdir()
    (doc_root / ".htaccess").write_text("RewriteEngine On\n", encoding="utf-8")

    config = parse_apache_config(
        f'DocumentRoot "{_posix_path(doc_root)}"\n'
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert Path(result.found[0].directory_path).resolve() == doc_root.resolve()
    assert result.found[0].source_directory_block is None


def test_htaccess_document_root_in_virtualhost(tmp_path: Path) -> None:
    doc_root = tmp_path / "vhost_root"
    doc_root.mkdir()
    (doc_root / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        "<VirtualHost *:80>\n"
        f'    DocumentRoot "{_posix_path(doc_root)}"\n'
        "</VirtualHost>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert result.found[0].source_directory_block is None


def test_htaccess_deduplicates_same_directory(tmp_path: Path) -> None:
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        f'DocumentRoot "{_posix_path(web_dir)}"\n'
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1


def test_htaccess_regex_directory_skipped(tmp_path: Path) -> None:
    """<Directory ~ "regex"> blocks should not trigger .htaccess lookup."""
    config = parse_apache_config(
        '<Directory ~ "^/var/www/(pub|priv)">\n'
        "    AllowOverride None\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert result.found == []
    assert result.issues == []


def test_htaccess_directory_without_args_skipped() -> None:
    """<Directory> with no path argument should be safely skipped."""
    config = parse_apache_config(
        "<Directory>\n"
        "    AllowOverride None\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, "httpd.conf")

    assert result.found == []
    assert result.issues == []


def test_htaccess_integrated_in_analyze(tmp_path: Path) -> None:
    """discover_htaccess_files is called during analyze_apache_config."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".htaccess").write_text(
        "<IfModule broken\n",  # malformed -- no closing >
        encoding="utf-8",
    )

    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            f'<Directory "{_posix_path(web_dir)}">\n'
            "    AllowOverride All\n"
            "</Directory>\n"
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
    issue_codes = [i.code for i in result.issues]
    assert "htaccess_parse_error" in issue_codes


def test_htaccess_relative_directory_path(tmp_path: Path) -> None:
    """Relative <Directory> path resolved against config file's parent dir."""
    site_dir = tmp_path / "conf" / "site"
    site_dir.mkdir(parents=True)
    (site_dir / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config_path = tmp_path / "conf" / "httpd.conf"
    config = parse_apache_config(
        '<Directory "site">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(config_path))

    assert len(result.found) == 1
    assert Path(result.found[0].directory_path).resolve() == site_dir.resolve()


def test_htaccess_relative_document_root(tmp_path: Path) -> None:
    """Relative DocumentRoot resolved against config file's parent dir."""
    htdocs = tmp_path / "conf" / "htdocs"
    htdocs.mkdir(parents=True)
    (htdocs / ".htaccess").write_text("RewriteEngine On\n", encoding="utf-8")

    config_path = tmp_path / "conf" / "httpd.conf"
    config = parse_apache_config(
        'DocumentRoot "htdocs"\n'
    )
    result = discover_htaccess_files(config, str(config_path))

    assert len(result.found) == 1
    assert Path(result.found[0].directory_path).resolve() == htdocs.resolve()


def test_htaccess_stored_in_analysis_metadata(tmp_path: Path) -> None:
    """Discovered htaccess files are stored in AnalysisResult.metadata."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            f'<Directory "{_posix_path(web_dir)}">\n'
            "    AllowOverride All\n"
            "</Directory>\n"
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
    assert "htaccess_files" in result.metadata
    htaccess_files = result.metadata["htaccess_files"]
    assert len(htaccess_files) == 1
    assert htaccess_files[0].ast.nodes[0].name == "Options"


def test_htaccess_read_error_produces_issue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """OSError during .htaccess read produces htaccess_read_error issue."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    htaccess = web_dir / ".htaccess"
    htaccess.write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )

    original_read_text = Path.read_text

    def failing_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == ".htaccess":
            raise OSError("Permission denied")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing_read_text)
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert result.found == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "htaccess_read_error"


def test_htaccess_access_file_name_in_toplevel_ifmodule(tmp_path: Path) -> None:
    """AccessFileName inside top-level <IfModule> is server-scope -- found."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".override").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        "<IfModule mod_access.c>\n"
        "    AccessFileName .override\n"
        "</IfModule>\n"
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert Path(result.found[0].htaccess_path).name == ".override"


def test_htaccess_access_file_name_in_toplevel_ifdefine(tmp_path: Path) -> None:
    """AccessFileName inside top-level <IfDefine> is also server-scope."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".override").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        "<IfDefine PROD>\n"
        "    AccessFileName .override\n"
        "</IfDefine>\n"
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert Path(result.found[0].htaccess_path).name == ".override"


def test_htaccess_access_file_name_inside_directory_ignored(tmp_path: Path) -> None:
    """AccessFileName inside <Directory> is directory-scope -- ignored for global discovery."""
    dir_a = tmp_path / "app"
    dir_a.mkdir()
    (dir_a / ".appaccess").write_text("Options -Indexes\n", encoding="utf-8")

    dir_b = tmp_path / "site"
    dir_b.mkdir()
    (dir_b / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        f'<Directory "{_posix_path(dir_a)}">\n'
        "    AccessFileName .appaccess\n"
        "    AllowOverride Options\n"
        "</Directory>\n"
        f'<Directory "{_posix_path(dir_b)}">\n'
        "    AllowOverride Options\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    # dir_b uses default .htaccess (not .appaccess from dir_a's scope)
    found_paths = {Path(f.htaccess_path).name for f in result.found}
    assert ".htaccess" in found_paths


# ---------------------------------------------------------------------------
# Phase 2.3: AllowOverride semantics
# ---------------------------------------------------------------------------


class TestExtractAllowOverride:
    def test_allowoverride_none(self) -> None:
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride None\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        assert extract_allowoverride(block) == frozenset()

    def test_allowoverride_all(self) -> None:
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride All\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        assert extract_allowoverride(block) == ALL_OVERRIDE_CATEGORIES

    def test_allowoverride_specific_categories(self) -> None:
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride FileInfo AuthConfig\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        result = extract_allowoverride(block)
        assert result == frozenset({"FileInfo", "AuthConfig"})

    def test_allowoverride_case_insensitive(self) -> None:
        """Apache accepts lowercase category names; we should too."""
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride fileinfo authconfig\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        result = extract_allowoverride(block)
        assert result == frozenset({"FileInfo", "AuthConfig"})

    def test_allowoverride_absent(self) -> None:
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    Options -Indexes\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        assert extract_allowoverride(block) is None

    def test_allowoverride_indexes_options(self) -> None:
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride Indexes Options\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        assert extract_allowoverride(block) == frozenset({"Indexes", "Options"})


class TestFilterHtaccessByAllowOverride:
    def test_none_filters_everything(self) -> None:
        ast = parse_apache_config(
            "Options Indexes\n"
            "RewriteEngine On\n"
            "DirectoryIndex index.php\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, frozenset())
        assert len(filtered.nodes) == 0

    def test_all_passes_everything(self) -> None:
        ast = parse_apache_config(
            "Options Indexes\n"
            "RewriteEngine On\n"
            "DirectoryIndex index.php\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, ALL_OVERRIDE_CATEGORIES)
        assert len(filtered.nodes) == 3

    def test_fileinfo_only(self) -> None:
        ast = parse_apache_config(
            "Options Indexes\n"
            "RewriteEngine On\n"
            "DirectoryIndex index.php\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, frozenset({"FileInfo"}))
        names = [n.name for n in filtered.nodes]
        assert "RewriteEngine" in names
        assert "Options" not in names
        assert "DirectoryIndex" not in names

    def test_options_only(self) -> None:
        ast = parse_apache_config(
            "Options Indexes\n"
            "RewriteEngine On\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, frozenset({"Options"}))
        names = [n.name for n in filtered.nodes]
        assert names == ["Options"]

    def test_unknown_directives_blocked(self) -> None:
        """Directives not in the category map are blocked."""
        ast = parse_apache_config(
            "CustomDirective value\n"
            "Options Indexes\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, frozenset({"Options"}))
        names = [n.name for n in filtered.nodes]
        assert "CustomDirective" not in names
        assert "Options" in names

    def test_block_filtered_by_category(self) -> None:
        """<LimitExcept> block is filtered when Limit category not allowed."""
        ast = parse_apache_config(
            "<LimitExcept GET POST>\n"
            "    Require all denied\n"
            "</LimitExcept>\n"
            "Options -Indexes\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, frozenset({"Options"}))
        assert len(filtered.nodes) == 1
        assert filtered.nodes[0].name == "Options"

    def test_authconfig_indexes_combo(self) -> None:
        ast = parse_apache_config(
            "AuthType Basic\n"
            "AuthName \"Restricted\"\n"
            "Require valid-user\n"
            "Options Indexes\n"
            "DirectoryIndex index.html\n"
            "RewriteEngine On\n"
        )
        filtered = filter_htaccess_by_allowoverride(
            ast, frozenset({"AuthConfig", "Indexes"})
        )
        names = [n.name for n in filtered.nodes]
        assert "AuthType" in names
        assert "AuthName" in names
        assert "Require" in names
        assert "DirectoryIndex" in names
        assert "Options" not in names
        assert "RewriteEngine" not in names


class TestAllowOverrideAllRule:
    def test_allowoverride_all_fires(self, tmp_path: Path) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
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
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" in ids

    def test_allowoverride_absent_fires(self, tmp_path: Path) -> None:
        """Missing AllowOverride -> treated as worst-case All -> fires."""
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    Options -Indexes\n"
                "</Directory>\n"
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
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" in ids

    def test_allowoverride_none_does_not_fire(self, tmp_path: Path) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
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
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" not in ids

    def test_allowoverride_specific_does_not_fire(self, tmp_path: Path) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride FileInfo\n"
                "</Directory>\n"
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
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" not in ids

    def test_find_effective_allowoverride_excludes_self(self) -> None:
        from webconf_audit.local.apache.rules.allowoverride_all import (
            _find_effective_allowoverride,
            _iter_directory_blocks,
        )

        ast = parse_apache_config(
            '<Directory "/var/www/restricted">\n'
            "    AllowOverride FileInfo\n"
            "</Directory>\n",
            file_path="/etc/httpd/httpd.conf",
        )
        blocks = _iter_directory_blocks(ast.nodes)
        assert len(blocks) == 1

        effective = _find_effective_allowoverride(blocks[0], blocks)

        assert effective is None

    def test_find_effective_allowoverride_returns_parent_not_self(self) -> None:
        from webconf_audit.local.apache.rules.allowoverride_all import (
            _find_effective_allowoverride,
            _iter_directory_blocks,
        )

        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride All\n"
            "</Directory>\n"
            '<Directory "/var/www/restricted">\n'
            "    AllowOverride FileInfo\n"
            "</Directory>\n",
            file_path="/etc/httpd/httpd.conf",
        )
        blocks = _iter_directory_blocks(ast.nodes)
        assert len(blocks) == 2
        child_block = next(b for b in blocks if b.args[0].endswith("restricted"))

        effective = _find_effective_allowoverride(child_block, blocks)

        assert effective == ALL_OVERRIDE_CATEGORIES

    def test_find_effective_allowoverride_skips_same_path_peer(self) -> None:
        from webconf_audit.local.apache.rules.allowoverride_all import (
            _find_effective_allowoverride,
            _iter_directory_blocks,
        )

        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride None\n"
            "</Directory>\n"
            '<Directory "/var/www">\n'
            "    AllowOverride All\n"
            "</Directory>\n",
            file_path="/etc/httpd/httpd.conf",
        )
        blocks = _iter_directory_blocks(ast.nodes)
        assert len(blocks) == 2

        effective_for_first = _find_effective_allowoverride(blocks[0], blocks)
        effective_for_second = _find_effective_allowoverride(blocks[1], blocks)

        assert effective_for_first is None
        assert effective_for_second is None

    def test_find_effective_allowoverride_prefers_later_equal_parent(self) -> None:
        from webconf_audit.local.apache.rules.allowoverride_all import (
            _find_effective_allowoverride,
            _iter_directory_blocks,
        )

        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride All\n"
            "</Directory>\n"
            '<Directory "/var/www">\n'
            "    AllowOverride None\n"
            "</Directory>\n"
            '<Directory "/var/www/restricted">\n'
            "    Options -Indexes\n"
            "</Directory>\n",
            file_path="/etc/httpd/httpd.conf",
        )
        blocks = _iter_directory_blocks(ast.nodes)
        assert len(blocks) == 3
        child_block = next(b for b in blocks if b.args[0].endswith("restricted"))

        effective = _find_effective_allowoverride(child_block, blocks)

        assert effective == frozenset()

    def test_allowoverride_all_then_none_at_same_path_does_not_fire(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                '<Directory "/var/www">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
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
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" not in ids

    def test_allowoverride_later_parent_none_suppresses_child_inheritance(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                '<Directory "/var/www">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                '<Directory "/var/www/restricted">\n'
                "    Options -Indexes\n"
                "</Directory>\n"
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
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" not in ids

    def test_allowoverride_repeated_all_at_same_path_fires_once_at_winner(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
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
        ao_findings = [
            f for f in result.findings
            if f.rule_id == "apache.allowoverride_all_in_directory"
        ]
        assert len(ao_findings) == 1
        # Finding points at the later declaration whose directive wins the merge.
        assert ao_findings[0].location.line == 4

    def test_allowoverride_repeated_no_directive_at_same_path_fires_once(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    Options -Indexes\n"
                "</Directory>\n"
                '<Directory "/var/www">\n'
                "    Options +FollowSymLinks\n"
                "</Directory>\n"
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
        ao_findings = [
            f for f in result.findings
            if f.rule_id == "apache.allowoverride_all_in_directory"
        ]
        assert len(ao_findings) == 1
        # Finding points at the earliest declaration at the path.
        assert ao_findings[0].location.line == 1


class TestHtaccessSecurityDirectiveRule:
    def test_options_in_htaccess_fires(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
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
        ids = [f.rule_id for f in result.findings]
        assert "apache.htaccess_contains_security_directive" in ids

    def test_allowoverride_none_blocks_htaccess_rule(self, tmp_path: Path) -> None:
        """AllowOverride None -> .htaccess ignored -> no security override finding."""
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
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
        ids = [f.rule_id for f in result.findings]
        assert "apache.htaccess_contains_security_directive" not in ids

    def test_allowoverride_fileinfo_blocks_options(self, tmp_path: Path) -> None:
        """AllowOverride FileInfo -> Options directive in .htaccess is filtered out."""
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text(
            "Options Indexes\nRewriteEngine On\n",
            encoding="utf-8",
        )

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride FileInfo\n"
                "</Directory>\n"
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
        overrides = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        # Options is blocked by FileInfo-only override,
        # but Header (FileInfo) would pass -- here only RewriteEngine which is not security-sensitive
        assert len(overrides) == 0

    def test_header_in_htaccess_fires(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text(
            "Header unset X-Content-Type-Options\n",
            encoding="utf-8",
        )

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride FileInfo\n"
                "</Directory>\n"
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
        overrides = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        assert len(overrides) == 1
        assert "Header" in overrides[0].title

    def test_no_htaccess_no_findings(self, tmp_path: Path) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
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
        overrides = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        assert len(overrides) == 0

    def test_security_directive_inside_ifmodule(self, tmp_path: Path) -> None:
        """Security directives inside <IfModule> in .htaccess are detected."""
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text(
            "<IfModule mod_headers.c>\n"
            "    Header unset X-Powered-By\n"
            "</IfModule>\n",
            encoding="utf-8",
        )

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride FileInfo\n"
                "</Directory>\n"
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
        overrides = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        assert len(overrides) == 1
        assert "Header" in overrides[0].title


# ---------------------------------------------------------------------------
# Phase 2.3 bugfixes: AccessFileName scoping + AllowOverride inheritance
# ---------------------------------------------------------------------------


class TestAccessFileNameScoping:
    def test_nested_accessfilename_does_not_affect_siblings(self, tmp_path: Path) -> None:
        """AccessFileName inside <Directory> must not change discovery for other dirs."""
        dir_a = tmp_path / "app"
        dir_a.mkdir()
        (dir_a / ".appaccess").write_text("Options Indexes\n", encoding="utf-8")

        dir_b = tmp_path / "site"
        dir_b.mkdir()
        (dir_b / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            f'<Directory "{_posix_path(dir_a)}">\n'
            "    AccessFileName .appaccess\n"
            "    AllowOverride Options\n"
            "</Directory>\n"
            f'<Directory "{_posix_path(dir_b)}">\n'
            "    AllowOverride Options\n"
            "</Directory>\n",
            encoding="utf-8",
        )
        result = discover_htaccess_files(
            parse_apache_config(config_path.read_text(encoding="utf-8")),
            str(config_path),
        )
        # dir_b should find .htaccess (default), not .appaccess
        found_paths = {Path(f.htaccess_path).name for f in result.found}
        assert ".htaccess" in found_paths

    def test_toplevel_accessfilename_applies_to_all(self, tmp_path: Path) -> None:
        """Top-level AccessFileName changes discovery for all directories."""
        dir_a = tmp_path / "www"
        dir_a.mkdir()
        (dir_a / ".override").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            "AccessFileName .override\n"
            f'<Directory "{_posix_path(dir_a)}">\n'
            "    AllowOverride Options\n"
            "</Directory>\n",
            encoding="utf-8",
        )
        result = discover_htaccess_files(
            parse_apache_config(config_path.read_text(encoding="utf-8")),
            str(config_path),
        )
        assert len(result.found) == 1
        assert Path(result.found[0].htaccess_path).name == ".override"


class TestAllowOverrideInheritance:
    def test_parent_allowoverride_none_blocks_child_docroot(self, tmp_path: Path) -> None:
        """<Directory> AllowOverride None should block .htaccess in child DocumentRoot."""
        parent_dir = tmp_path / "www"
        parent_dir.mkdir()
        child_dir = parent_dir / "site"
        child_dir.mkdir()
        (child_dir / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(parent_dir)}">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                f'DocumentRoot "{_posix_path(child_dir)}"\n'
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
        security_findings = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        # Parent <Directory> has AllowOverride None -> child .htaccess should be blocked
        assert len(security_findings) == 0

    def test_parent_allowoverride_all_allows_child_docroot(self, tmp_path: Path) -> None:
        """<Directory> AllowOverride All allows .htaccess in child DocumentRoot."""
        parent_dir = tmp_path / "www"
        parent_dir.mkdir()
        child_dir = parent_dir / "site"
        child_dir.mkdir()
        (child_dir / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(parent_dir)}">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                f'DocumentRoot "{_posix_path(child_dir)}"\n'
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
        security_findings = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        assert len(security_findings) == 1

    def test_parent_allowoverride_none_blocks_child_directory(self, tmp_path: Path) -> None:
        """Inherited AllowOverride None should block child Directory .htaccess too."""
        parent_dir = tmp_path / "var"
        parent_dir.mkdir()
        child_dir = parent_dir / "www"
        child_dir.mkdir()
        (child_dir / ".htaccess").write_text(
            "Header unset X-Frame-Options\n",
            encoding="utf-8",
        )

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(parent_dir)}">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                f'<Directory "{_posix_path(child_dir)}">\n'
                "    Options -Indexes\n"
                "</Directory>\n"
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
        relevant_ids = {
            finding.rule_id
            for finding in result.findings
            if finding.rule_id in {
                "apache.allowoverride_all_in_directory",
                "apache.htaccess_contains_security_directive",
            }
        }
        assert relevant_ids == set()

    def test_sibling_dir_not_covered_by_prefix_match(self, tmp_path: Path) -> None:
        """/var/www must NOT cover /var/www2 -- path boundary check."""
        www_dir = tmp_path / "www"
        www_dir.mkdir()
        www2_dir = tmp_path / "www2"
        www2_dir.mkdir()
        site_dir = www2_dir / "site"
        site_dir.mkdir()
        (site_dir / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(www_dir)}">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                f'DocumentRoot "{_posix_path(site_dir)}"\n'
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
        security_findings = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        # /var/www AllowOverride None must NOT block /var/www2/site/.htaccess
        assert len(security_findings) == 1


# ---------------------------------------------------------------------------
# Phase 2.4: Effective config reconstruction
# ---------------------------------------------------------------------------


class TestBuildEffectiveConfig:
    def test_global_directives_only(self) -> None:
        ast = parse_apache_config("ServerTokens Prod\nServerSignature Off\n")
        ec = build_effective_config(ast, "/var/www")
        assert "servertokens" in ec.directives
        assert ec.directives["servertokens"].args == ["Prod"]
        assert ec.directives["servertokens"].origin.layer == "global"

    def test_global_directives_inside_toplevel_ifmodule(self) -> None:
        ast = parse_apache_config(
            "<IfModule mod_core.c>\n"
            "    ServerSignature Off\n"
            "    ServerTokens Prod\n"
            "</IfModule>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        assert ec.directives["serversignature"].args == ["Off"]
        assert ec.directives["serversignature"].origin.layer == "global"
        assert ec.directives["servertokens"].args == ["Prod"]

    def test_directory_overrides_global(self) -> None:
        ast = parse_apache_config(
            "ServerTokens Prod\n"
            '<Directory "/var/www">\n'
            "    ServerTokens Full\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        assert ec.directives["servertokens"].args == ["Full"]
        assert ec.directives["servertokens"].origin.layer == "directory"
        # Override chain records the global value
        assert len(ec.directives["servertokens"].override_chain) == 1
        assert ec.directives["servertokens"].override_chain[0].layer == "global"

    def test_directory_sorting_shortest_first(self) -> None:
        ast = parse_apache_config(
            '<Directory "/">\n'
            "    Options -Indexes\n"
            "</Directory>\n"
            '<Directory "/var/www">\n'
            "    Options Indexes\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        # /var/www (longer) applied last -> wins
        assert "indexes" in [a.lower() for a in ec.directives["options"].args]

    def test_options_merge_plus_minus(self) -> None:
        ast = parse_apache_config(
            "Options Indexes FollowSymLinks\n"
            '<Directory "/var/www">\n'
            "    Options -Indexes +ExecCGI\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        opts = set(ec.directives["options"].args)
        assert "execcgi" in opts
        assert "followsymlinks" in opts
        assert "indexes" not in opts

    def test_options_replace_without_prefix(self) -> None:
        ast = parse_apache_config(
            "Options Indexes FollowSymLinks\n"
            '<Directory "/var/www">\n'
            "    Options None\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        # Without +/- prefix -> last-wins replacement
        assert ec.directives["options"].args == ["None"]

    def test_options_none_cleared_before_relative_merge(self, tmp_path: Path) -> None:
        ast = parse_apache_config(
            "Options None\n"
            f'<Directory "{_posix_path(tmp_path)}">\n'
            "    AllowOverride Options\n"
            "</Directory>\n"
        )
        htaccess_ast = parse_apache_config("Options +Indexes\n")
        htf = HtaccessFile(
            directory_path=str(tmp_path),
            htaccess_path=str(tmp_path / ".htaccess"),
            ast=htaccess_ast,
            source_directory_block=ast.nodes[1],
        )
        ec = build_effective_config(ast, str(tmp_path), htaccess_file=htf)
        assert ec.directives["options"].args == ["indexes"]

    def test_htaccess_layer_applied(self, tmp_path: Path) -> None:
        ast = parse_apache_config(
            "Options -Indexes\n"
            f'<Directory "{_posix_path(tmp_path)}">\n'
            "    AllowOverride Options\n"
            "</Directory>\n"
        )
        htaccess_ast = parse_apache_config("Options +Indexes\n")
        htf = HtaccessFile(
            directory_path=str(tmp_path),
            htaccess_path=str(tmp_path / ".htaccess"),
            ast=htaccess_ast,
            source_directory_block=ast.nodes[1],
        )
        ec = build_effective_config(ast, str(tmp_path), htaccess_file=htf)
        opts = set(ec.directives["options"].args)
        assert "indexes" in opts

    def test_htaccess_wrapped_directive_applied(self, tmp_path: Path) -> None:
        ast = parse_apache_config(
            "Options -Indexes\n"
            f'<Directory "{_posix_path(tmp_path)}">\n'
            "    AllowOverride Options\n"
            "</Directory>\n"
        )
        htaccess_ast = parse_apache_config(
            "<IfModule mod_autoindex.c>\n"
            "    Options +Indexes\n"
            "</IfModule>\n"
        )
        htf = HtaccessFile(
            directory_path=str(tmp_path),
            htaccess_path=str(tmp_path / ".htaccess"),
            ast=htaccess_ast,
            source_directory_block=ast.nodes[1],
        )
        ec = build_effective_config(ast, str(tmp_path), htaccess_file=htf)
        opts = set(ec.directives["options"].args)
        assert "indexes" in opts

    def test_htaccess_filtered_by_allowoverride(self, tmp_path: Path) -> None:
        ast = parse_apache_config(
            "Options -Indexes\n"
            f'<Directory "{_posix_path(tmp_path)}">\n'
            "    AllowOverride FileInfo\n"
            "</Directory>\n"
        )
        htaccess_ast = parse_apache_config("Options +Indexes\n")
        htf = HtaccessFile(
            directory_path=str(tmp_path),
            htaccess_path=str(tmp_path / ".htaccess"),
            ast=htaccess_ast,
            source_directory_block=ast.nodes[1],
        )
        ec = build_effective_config(ast, str(tmp_path), htaccess_file=htf)
        # Options not in AllowOverride FileInfo -> filtered out -> no change
        opts = set(ec.directives["options"].args)
        assert "indexes" not in opts

    def test_no_directives(self) -> None:
        ast = parse_apache_config("")
        ec = build_effective_config(ast, "/var/www")
        assert ec.directives == {}

    def test_unrelated_directory_not_applied(self) -> None:
        ast = parse_apache_config(
            "ServerTokens Prod\n"
            '<Directory "/other">\n'
            "    ServerTokens Full\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        assert ec.directives["servertokens"].args == ["Prod"]


class TestHtaccessWeakensSecurity:
    def test_htaccess_adds_indexes(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Options +Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "Options -Indexes\n"
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride Options\n"
                "</Directory>\n"
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
        weakens = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_weakens_security"
        ]
        assert len(weakens) == 1
        assert "indexes" in weakens[0].title.lower()

    def test_htaccess_no_weakening(self, tmp_path: Path) -> None:
        """Non-dangerous options change should not fire."""
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Header set X-Custom value\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "Options -Indexes\n"
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride FileInfo\n"
                "</Directory>\n"
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
        weakens = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_weakens_security"
        ]
        assert len(weakens) == 0

    def test_allowoverride_none_blocks_weakening(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Options +Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "Options -Indexes\n"
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
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
        weakens = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_weakens_security"
        ]
        assert len(weakens) == 0

    def test_htaccess_adds_execcgi(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Options +ExecCGI\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride Options\n"
                "</Directory>\n"
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
        weakens = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_weakens_security"
        ]
        assert len(weakens) == 1
        assert "execcgi" in weakens[0].title.lower()

    def test_wrapped_htaccess_directive_weakens_security(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text(
            "<IfModule mod_autoindex.c>\n"
            "    Options +Indexes\n"
            "</IfModule>\n",
            encoding="utf-8",
        )

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "Options -Indexes\n"
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride Options\n"
                "</Directory>\n"
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
        weakens = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_weakens_security"
        ]
        assert len(weakens) == 1
        assert "indexes" in weakens[0].title.lower()

    def test_toplevel_ifmodule_baseline_enables_serversignature_override_detection(
        self,
    ) -> None:
        config_ast = parse_apache_config(
            "<IfModule mod_core.c>\n"
            "    ServerSignature Off\n"
            "</IfModule>\n"
        )
        htaccess_ast = parse_apache_config("ServerSignature On\n")
        htaccess_file = HtaccessFile(
            directory_path="/var/www",
            htaccess_path="/var/www/.htaccess",
            ast=htaccess_ast,
            source_directory_block=None,
        )

        findings = find_htaccess_weakens_security(config_ast, [htaccess_file])
        assert len(findings) == 1
        assert findings[0].rule_id == "apache.htaccess_weakens_security"
        assert "serversignature" in findings[0].title.lower()

    def test_override_chain_tracked(self, tmp_path: Path) -> None:
        """Effective config records the override chain."""
        ast = parse_apache_config(
            "ServerTokens Prod\n"
            f'<Directory "{_posix_path(tmp_path)}">\n'
            "    ServerTokens Full\n"
            "    AllowOverride All\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, str(tmp_path))
        st = ec.directives["servertokens"]
        assert st.args == ["Full"]
        assert len(st.override_chain) == 1
        assert st.override_chain[0].layer == "global"


class TestHtaccessRulePack:
    def test_htaccess_disables_security_headers(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Header unset X-Frame-Options\n",
            allowoverride="FileInfo",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_disables_security_headers"
        ]
        assert len(findings) == 1
        assert "x-frame-options" in findings[0].title.lower()

    def test_htaccess_disables_security_headers_blocked_by_allowoverride(
        self,
        tmp_path: Path,
    ) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Header unset X-Frame-Options\n",
            allowoverride="Options",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_disables_security_headers"
        ]
        assert findings == []

    def test_htaccess_enables_cgi(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options +ExecCGI\n",
            allowoverride="Options",
        )
        findings = [
            f for f in result.findings if f.rule_id == "apache.htaccess_enables_cgi"
        ]
        assert len(findings) == 1

    def test_htaccess_options_all_enables_cgi(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options All\n",
            allowoverride="Options",
        )
        findings = [
            f for f in result.findings if f.rule_id == "apache.htaccess_enables_cgi"
        ]
        assert len(findings) == 1

    def test_htaccess_enables_cgi_blocked_by_allowoverride(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options +ExecCGI\n",
            allowoverride="FileInfo",
        )
        findings = [
            f for f in result.findings if f.rule_id == "apache.htaccess_enables_cgi"
        ]
        assert findings == []

    def test_htaccess_enables_directory_listing(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options +Indexes\n",
            allowoverride="Options",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_enables_directory_listing"
        ]
        assert len(findings) == 1

    def test_htaccess_options_all_enables_directory_listing(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options All\n",
            allowoverride="Options",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_enables_directory_listing"
        ]
        assert len(findings) == 1

    def test_htaccess_enables_directory_listing_blocked_by_allowoverride(
        self,
        tmp_path: Path,
    ) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options +Indexes\n",
            allowoverride="FileInfo",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_enables_directory_listing"
        ]
        assert findings == []

    def test_htaccess_rewrite_without_limit(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "RewriteEngine On\nRewriteRule ^foo$ /bar [R=302,L]\n",
            allowoverride="FileInfo",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_rewrite_without_limit"
        ]
        assert len(findings) == 1

    def test_htaccess_rewrite_with_condition_not_reported(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            (
                "RewriteEngine On\n"
                "RewriteCond %{REQUEST_URI} ^/foo$\n"
                "RewriteRule ^foo$ /bar [R=302,L]\n"
            ),
            allowoverride="FileInfo",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_rewrite_without_limit"
        ]
        assert findings == []

    def test_directory_without_allowoverride(self, tmp_path: Path) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "\n".join(
                    [
                        "ServerSignature Off",
                        "ServerTokens Prod",
                        "TraceEnable Off",
                        "LimitRequestBody 102400",
                        "LimitRequestFields 100",
                        "ErrorLog logs/error_log",
                        "CustomLog logs/access_log combined",
                        'ErrorDocument 404 "/error/404.html"',
                        'ErrorDocument 500 "/error/500.html"',
                        f'<Directory "{_posix_path(tmp_path / "www")}">',
                        "    Options -Indexes",
                        "</Directory>",
                    ]
                )
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.directory_without_allowoverride"
        ]
        assert len(findings) == 1

    def test_directory_with_explicit_allowoverride_not_reported(
        self,
        tmp_path: Path,
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "\n".join(
                    [
                        "ServerSignature Off",
                        "ServerTokens Prod",
                        "TraceEnable Off",
                        "LimitRequestBody 102400",
                        "LimitRequestFields 100",
                        "ErrorLog logs/error_log",
                        "CustomLog logs/access_log combined",
                        'ErrorDocument 404 "/error/404.html"',
                        'ErrorDocument 500 "/error/500.html"',
                        f'<Directory "{_posix_path(tmp_path / "www")}">',
                        "    AllowOverride None",
                        "    Options -Indexes",
                        "</Directory>",
                    ]
                )
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.directory_without_allowoverride"
        ]
        assert findings == []

    def test_htaccess_auth_without_require(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            'AuthType Basic\nAuthName "Restricted"\n',
            allowoverride="AuthConfig",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_auth_without_require"
        ]
        assert len(findings) == 1

    def test_htaccess_auth_with_require_not_reported(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            'AuthType Basic\nAuthName "Restricted"\nRequire valid-user\n',
            allowoverride="AuthConfig",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_auth_without_require"
        ]
        assert findings == []


def test_extract_virtualhost_contexts_reads_server_names_and_aliases() -> None:
    ast = parse_apache_config(
        "<VirtualHost *:80>\n"
        "    ServerName example.test\n"
        "    ServerAlias www.example.test api.example.test\n"
        "</VirtualHost>\n"
        "<IfModule mod_ssl.c>\n"
        "    <VirtualHost *:443>\n"
        "    </VirtualHost>\n"
        "</IfModule>\n"
    )

    contexts = extract_virtualhost_contexts(ast)

    assert len(contexts) == 2
    assert contexts[0].server_name == "example.test"
    assert contexts[0].server_aliases == ["www.example.test", "api.example.test"]
    assert contexts[0].listen_address == "*:80"
    assert contexts[0].optional_ancestor_names == ()
    assert contexts[1].server_name is None
    assert contexts[1].listen_address == "*:443"
    assert contexts[1].optional_ancestor_names == ("ifmodule",)


def test_select_applicable_virtualhosts_matches_serveralias() -> None:
    ast = parse_apache_config(
        "<VirtualHost *:80>\n"
        "    ServerName example.test\n"
        "    ServerAlias www.example.test api.example.test\n"
        "</VirtualHost>\n"
        "<VirtualHost *:80>\n"
        "    ServerName admin.example.test\n"
        "</VirtualHost>\n"
    )

    contexts = extract_virtualhost_contexts(ast)
    selected = select_applicable_virtualhosts(contexts, target_host="api.example.test")

    assert len(selected) == 1
    assert selected[0].server_name == "example.test"


def test_build_server_effective_config_applies_virtualhost_override() -> None:
    ast = parse_apache_config(
        "ServerTokens Prod\n"
        "<VirtualHost *:80>\n"
        "    ServerName example.test\n"
        "    ServerTokens Full\n"
        "</VirtualHost>\n"
    )

    context = extract_virtualhost_contexts(ast)[0]
    effective = build_server_effective_config(ast, virtualhost_context=context)

    assert effective.directives["servertokens"].args == ["Full"]
    assert effective.directives["servertokens"].origin.layer == "virtualhost:example.test"


def test_build_effective_config_applies_location_after_directory() -> None:
    ast = parse_apache_config(
        "Options -Indexes\n"
        '<Directory "/var/www">\n'
        "    Options -Indexes\n"
        "</Directory>\n"
        '<Location "/admin">\n'
        "    Options +Indexes\n"
        "</Location>\n"
    )

    effective = build_effective_config(ast, "/var/www", location_path="/admin")

    assert "indexes" in set(effective.directives["options"].args)
    assert effective.directives["options"].origin.layer == "location:/admin"


def test_build_effective_config_accumulates_header_directives() -> None:
    ast = parse_apache_config(
        "Header set X-Frame-Options DENY\n"
        "<VirtualHost *:80>\n"
        "    ServerName example.test\n"
        "    Header append X-Frame-Options SAMEORIGIN\n"
        "    Header set Strict-Transport-Security max-age=31536000\n"
        "</VirtualHost>\n"
    )

    context = extract_virtualhost_contexts(ast)[0]
    effective = build_effective_config(
        ast,
        "/var/www",
        virtualhost_context=context,
    )

    header_args = effective.directives["header"].args
    assert isinstance(header_args[0], list)
    assert ["set", "X-Frame-Options", "DENY"] in header_args
    assert ["append", "X-Frame-Options", "SAMEORIGIN"] in header_args
    assert ["set", "Strict-Transport-Security", "max-age=31536000"] in header_args


def test_analyze_apache_config_reports_virtualhost_specific_server_tokens(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "<VirtualHost *:80>",
                    "    ServerName example.test",
                    "</VirtualHost>",
                    "<VirtualHost *:80>",
                    "    ServerName admin.example.test",
                    "    ServerTokens Full",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.server_tokens_not_prod"
    ]

    assert result.issues == []
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(config_path)
    assert findings[0].location.line == 15


def test_analyze_apache_config_describes_inherited_virtualhost_server_tokens(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Full",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "<VirtualHost *:80>",
                    "    ServerName inherited.example.test",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.server_tokens_not_prod"
    ]

    assert result.issues == []
    assert len(findings) == 1
    # Assert the *semantic* parts of the description (directive name,
    # offending value, scope) instead of the whole sentence -- a harmless
    # rewording of the human-readable text would otherwise break the
    # test without any actual regression in rule behaviour.
    description = findings[0].description
    assert "ServerTokens" in description
    assert "Full" in description
    assert "inherits" in description
    assert "global scope" in description


def test_analyze_apache_config_reports_options_includes_in_location_block(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Location "/admin">',
                    "    Options Includes",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.options_includes_enabled"
    ]

    assert result.issues == []
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(config_path)
    assert findings[0].location.line == 11


# --- Block 2: analysis context tests ---


def test_analysis_contexts_global_when_no_virtualhost(tmp_path: Path) -> None:
    """Config without VirtualHost produces a single global analysis context."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    contexts = result.metadata.get("analysis_contexts")
    assert contexts is not None
    assert len(contexts) == 1
    assert contexts[0]["label"] == "global"
    assert contexts[0]["virtualhost"] is False


def test_analysis_contexts_per_virtualhost(tmp_path: Path) -> None:
    """Config with two VirtualHosts produces two analysis contexts."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                "<VirtualHost *:80>",
                "    ServerName alpha.test",
                f'    DocumentRoot "{_posix_path(tmp_path / "alpha")}"',
                "</VirtualHost>",
                "<VirtualHost *:80>",
                "    ServerName beta.test",
                f'    DocumentRoot "{_posix_path(tmp_path / "beta")}"',
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    contexts = result.metadata.get("analysis_contexts")
    assert contexts is not None
    assert len(contexts) == 2
    labels = {ctx["label"] for ctx in contexts}
    assert labels == {"alpha.test", "beta.test"}
    for ctx in contexts:
        assert ctx["virtualhost"] is True


def test_virtualhost_specific_document_root_changes_htaccess_discovery(
    tmp_path: Path,
) -> None:
    """Htaccess under VH-specific DocumentRoot is associated with that context."""
    alpha_dir = tmp_path / "alpha"
    alpha_dir.mkdir()
    (alpha_dir / ".htaccess").write_text("Options +Indexes\n", encoding="utf-8")

    beta_dir = tmp_path / "beta"
    beta_dir.mkdir()

    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                "<VirtualHost *:80>",
                "    ServerName alpha.test",
                f'    DocumentRoot "{_posix_path(alpha_dir)}"',
                f'    <Directory "{_posix_path(alpha_dir)}">',
                "        AllowOverride All",
                "    </Directory>",
                "</VirtualHost>",
                "<VirtualHost *:80>",
                "    ServerName beta.test",
                f'    DocumentRoot "{_posix_path(beta_dir)}"',
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    contexts = result.metadata["analysis_contexts"]
    alpha_ctx = next(c for c in contexts if c["label"] == "alpha.test")
    beta_ctx = next(c for c in contexts if c["label"] == "beta.test")
    assert alpha_ctx["htaccess_count"] == 1
    assert beta_ctx["htaccess_count"] == 0


def test_global_server_status_overridden_in_all_virtualhosts_no_false_positive(
    tmp_path: Path,
) -> None:
    """Global permissive Location is overridden safely in each VirtualHost."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                '<Location "/server-status">',
                "    SetHandler server-status",
                "</Location>",
                "<VirtualHost *:80>",
                "    ServerName site1.test",
                '    <Location "/server-status">',
                "        SetHandler server-status",
                "        Require ip 127.0.0.1",
                "    </Location>",
                "</VirtualHost>",
                "<VirtualHost *:80>",
                "    ServerName site2.test",
                '    <Location "/server-status">',
                "        SetHandler server-status",
                "        Require ip 10.0.0.0/8",
                "    </Location>",
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    server_status_findings = [
        f for f in result.findings
        if f.rule_id == "apache.server_status_exposed"
    ]
    assert server_status_findings == []


def test_options_indexes_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """Global <Directory> has Options Indexes but VH overrides with -Indexes.

    The effective-config-aware rule should NOT report a finding because
    the VH override disables directory listing in the effective scope.
    """
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "TraceEnable Off",
                "ServerTokens Prod",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                'ErrorDocument 404 "/error/404.html"',
                'ErrorDocument 500 "/error/500.html"',
                '<Directory "/var/www/html">',
                "    Options Indexes",
                "</Directory>",
                "<VirtualHost *:80>",
                "    ServerName safe.test",
                '    <Directory "/var/www/html">',
                "        Options -Indexes",
                "    </Directory>",
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    index_findings = [
        f for f in result.findings if f.rule_id == "apache.options_indexes"
    ]
    assert index_findings == []


# --- Block 3/5 regression: VH effective override suppresses Options-family ---


def _make_vh_override_config(
    tmp_path: Path,
    *,
    global_options: str,
    vh_options: str,
) -> str:
    """Create a config where a global <Directory> sets options and a VH overrides."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "TraceEnable Off",
                "ServerTokens Prod",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                'ErrorDocument 404 "/error/404.html"',
                'ErrorDocument 500 "/error/500.html"',
                '<Directory "/var/www">',
                f"    {global_options}",
                "</Directory>",
                "<VirtualHost *:80>",
                "    ServerName safe.test",
                '    <Directory "/var/www">',
                f"        {vh_options}",
                "    </Directory>",
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )
    return str(config_path)


def test_options_includes_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """VH overrides global Options Includes with -Includes -> no finding."""
    config = _make_vh_override_config(
        tmp_path,
        global_options="Options Includes",
        vh_options="Options -Includes",
    )
    result = analyze_apache_config(config)
    findings = [f for f in result.findings if f.rule_id == "apache.options_includes_enabled"]
    assert findings == [], (
        "Regression: options_includes_enabled fires despite VH -Includes override."
    )


def test_options_execcgi_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """VH overrides global Options ExecCGI with -ExecCGI -> no finding."""
    config = _make_vh_override_config(
        tmp_path,
        global_options="Options ExecCGI",
        vh_options="Options -ExecCGI",
    )
    result = analyze_apache_config(config)
    findings = [f for f in result.findings if f.rule_id == "apache.options_execcgi_enabled"]
    assert findings == [], (
        "Regression: options_execcgi_enabled fires despite VH -ExecCGI override."
    )


def test_options_multiviews_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """VH overrides global Options MultiViews with -MultiViews -> no finding."""
    config = _make_vh_override_config(
        tmp_path,
        global_options="Options MultiViews",
        vh_options="Options -MultiViews",
    )
    result = analyze_apache_config(config)
    findings = [f for f in result.findings if f.rule_id == "apache.options_multiviews_enabled"]
    assert findings == [], (
        "Regression: options_multiviews_enabled fires despite VH -MultiViews override."
    )


def test_index_options_fancyindexing_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """VH overrides global IndexOptions FancyIndexing -> no finding."""
    config = _make_vh_override_config(
        tmp_path,
        global_options="IndexOptions FancyIndexing",
        vh_options="IndexOptions -FancyIndexing",
    )
    result = analyze_apache_config(config)
    findings = [
        f for f in result.findings
        if f.rule_id == "apache.index_options_fancyindexing_enabled"
    ]
    assert findings == [], (
        "Regression: index_options_fancyindexing_enabled fires despite VH override."
    )


def test_index_options_scanhtmltitles_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """VH overrides global IndexOptions ScanHTMLTitles -> no finding."""
    config = _make_vh_override_config(
        tmp_path,
        global_options="IndexOptions ScanHTMLTitles",
        vh_options="IndexOptions -ScanHTMLTitles",
    )
    result = analyze_apache_config(config)
    findings = [
        f for f in result.findings
        if f.rule_id == "apache.index_options_scanhtmltitles_enabled"
    ]
    assert findings == [], (
        "Regression: index_options_scanhtmltitles_enabled fires despite VH override."
    )


def test_htaccess_discovery_prefers_later_same_path_allowoverride_block(
    tmp_path: Path,
) -> None:
    """Later same-path Directory blocks should win for AllowOverride inheritance."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".htaccess").write_text("Options +Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride None\n"
        "</Directory>\n"
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    source_block = result.found[0].source_directory_block
    assert source_block is not None
    assert extract_allowoverride(source_block) == ALL_OVERRIDE_CATEGORIES


def test_global_directory_findings_still_fire_when_virtualhosts_exist(tmp_path: Path) -> None:
    """Global Directory directives must still be evaluated in each VH effective view."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "TraceEnable Off",
                "ServerTokens Prod",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                'ErrorDocument 404 "/error/404.html"',
                'ErrorDocument 500 "/error/500.html"',
                '<Directory "/var/www/html">',
                "    Options Indexes Includes",
                "    IndexOptions FancyIndexing ScanHTMLTitles",
                "</Directory>",
                "<VirtualHost *:80>",
                "    ServerName demo.test",
                '    DocumentRoot "/var/www/html"',
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "apache.options_indexes" in rule_ids
    assert "apache.options_includes_enabled" in rule_ids
    assert "apache.index_options_fancyindexing_enabled" in rule_ids
    assert "apache.index_options_scanhtmltitles_enabled" in rule_ids


def test_options_indexes_negative_token_wins_when_mixed(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Indexes -Indexes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert not any(f.rule_id == "apache.options_indexes" for f in result.findings)
