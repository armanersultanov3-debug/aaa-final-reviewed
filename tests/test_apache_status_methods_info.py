from tests.apache_helpers import (
    Path,
    analyze_apache_config,
    _safe_apache_config,
    _with_backup_files_restriction,
)

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


def test_analyze_apache_config_accepts_server_status_requireall_ip_policy(
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
                    "    <RequireAll>",
                    "        Require ip 127.0.0.1",
                    "        Require all granted",
                    "    </RequireAll>",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.server_status_exposed"
        for finding in result.findings
    )


def test_analyze_apache_config_accepts_server_status_require_local(
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
                    "    Require local",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.server_status_exposed"
        for finding in result.findings
    )


def test_analyze_apache_config_reports_server_status_requireany_with_granted_branch(
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
                    "    <RequireAny>",
                    "        Require ip 127.0.0.1",
                    "        Require all granted",
                    "    </RequireAny>",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "apache.server_status_exposed"
        for finding in result.findings
    )


def test_analyze_apache_config_reports_server_status_legacy_allow_from_all(
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
                    "    Order deny,allow",
                    "    Deny from all",
                    "    Allow from all",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "apache.server_status_exposed"
        for finding in result.findings
    )


def test_analyze_apache_config_reports_sensitive_location_without_method_restriction(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Location "/admin">',
            "    Require all granted",
            "</Location>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.missing_http_method_restrictions"
    ]
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.file_path == str(config_path)


def test_analyze_apache_config_accepts_limitexcept_method_restriction(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Location "/admin">',
            "    <LimitExcept GET POST OPTIONS>",
            "        Require all denied",
            "    </LimitExcept>",
            "</Location>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_apache_config_accepts_limitexcept_deny_inside_authz_container(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Location "/admin">',
            "    <LimitExcept GET POST OPTIONS>",
            "        <RequireAll>",
            "            Require all denied",
            "        </RequireAll>",
            "    </LimitExcept>",
            "</Location>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_apache_config_accepts_nested_limit_method_restriction(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Location "/admin">',
            "    <LimitExcept GET>",
            "        <Limit POST>",
            "            Require all denied",
            "        </Limit>",
            "    </LimitExcept>",
            "</Location>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_apache_config_accepts_limit_method_restriction(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Location "/admin">',
            "    <Limit POST PUT DELETE PATCH>",
            "        Require all denied",
            "    </Limit>",
            "</Location>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_apache_config_accepts_require_method_restriction(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Location "/api">',
            "    Require method GET POST OPTIONS",
            "</Location>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_apache_config_accepts_require_method_inside_authz_container(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Location "/api">',
            "    <RequireAll>",
            "        Require method GET POST OPTIONS",
            "        Require all granted",
            "    </RequireAll>",
            "</Location>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_apache_config_reports_require_method_inside_requireany(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Location "/api">',
            "    <RequireAny>",
            "        Require method GET POST OPTIONS",
            "        Require all granted",
            "    </RequireAny>",
            "</Location>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.missing_http_method_restrictions"
    ]
    assert len(matching) == 1


def test_analyze_apache_config_reports_require_method_inside_requirenone(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Location "/api">',
            "    <RequireNone>",
            "        Require method GET POST OPTIONS",
            "    </RequireNone>",
            "</Location>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.missing_http_method_restrictions"
    ]
    assert len(matching) == 1


def test_analyze_apache_config_ignores_non_sensitive_location_without_method_restriction(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Location "/">',
            "    Require all granted",
            "</Location>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_apache_config_reports_virtualhost_sensitive_location_without_method_restriction(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            '    <LocationMatch "^/uploads/">',
            "        Require all granted",
            "    </LocationMatch>",
            "</VirtualHost>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.missing_http_method_restrictions"
    ]
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.file_path == str(config_path)
    assert matching[0].location.line == 13


def test_analyze_apache_config_ignores_sensitive_location_in_disabled_ifmodule(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            "LoadModule status_module modules/mod_status.so",
            "<IfModule !mod_status.c>",
            '    <Location "/admin">',
            "        Require all granted",
            "    </Location>",
            "</IfModule>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.missing_http_method_restrictions"
        for finding in result.findings
    )


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


def test_analyze_apache_config_accepts_server_info_requireall_ip_policy(
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
                    "    <RequireAll>",
                    "        Require ip 127.0.0.1",
                    "        Require all granted",
                    "    </RequireAll>",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.server_info_exposed"
        for finding in result.findings
    )


def test_analyze_apache_config_accepts_server_info_legacy_ip_allowlist(
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
                    "    Order deny,allow",
                    "    Deny from all",
                    "    Allow from 127.0.0.1",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.server_info_exposed"
        for finding in result.findings
    )


def test_analyze_apache_config_reports_server_info_requireany_with_granted_branch(
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
                    "    <RequireAny>",
                    "        Require ip 127.0.0.1",
                    "        Require all granted",
                    "    </RequireAny>",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "apache.server_info_exposed"
        for finding in result.findings
    )
