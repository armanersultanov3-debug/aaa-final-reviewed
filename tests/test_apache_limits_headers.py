from tests.apache_helpers import (
    Path,
    analyze_apache_config,
    pytest,
    _SAFE_SECURITY_HEADER_ALWAYS_LINES,
    _SAFE_SECURITY_HEADER_LINES,
    _posix_path,
    _safe_apache_config,
    _safe_apache_config_without_headers,
    _safe_apache_config_without_security_headers,
    _with_backup_files_restriction,
)

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
            _SAFE_SECURITY_HEADER_LINES["referrer-policy"],
            _SAFE_SECURITY_HEADER_ALWAYS_LINES["referrer-policy"],
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


@pytest.mark.parametrize(
    ("header_line", "rule_id"),
    [
        (
            "Header always set X-Frame-Options ALLOW-FROM https://legacy.example.test",
            "apache.x_frame_options_unsafe",
        ),
        (
            'Header always set X-Frame-Options ""',
            "apache.x_frame_options_unsafe",
        ),
        (
            "Header always set Referrer-Policy unsafe-url",
            "apache.referrer_policy_unsafe",
        ),
        (
            'Header always set Permissions-Policy "geolocation=*, microphone=()"',
            "apache.permissions_policy_unsafe",
        ),
    ],
)
def test_analyze_apache_config_reports_unsafe_security_header_policy(
    tmp_path: Path,
    header_line: str,
    rule_id: str,
) -> None:
    header_name = header_line.split(" set ", 1)[1].split()[0].lower()
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            header_line,
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


def test_analyze_apache_config_treats_unset_expr_as_header_condition(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header always set X-Frame-Options ALLOW-FROM https://legacy.example.test",
            "Header always unset X-Frame-Options expr=%{REQUEST_STATUS}",
            omit_headers={"x-frame-options"},
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    matching = {
        finding.rule_id
        for finding in result.findings
        if finding.rule_id
        in {
            "apache.missing_x_frame_options_header",
            "apache.x_frame_options_unsafe",
        }
    }
    assert result.issues == []
    assert matching == {
        "apache.missing_x_frame_options_header",
        "apache.x_frame_options_unsafe",
    }


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
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            header_line.replace("Header ", "Header always ", 1),
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
        _safe_apache_config_without_headers(
            "<VirtualHost *:80>",
            "    ServerName safe.test",
            "    Header unset X-Frame-Options",
            "    Header always set X-Frame-Options DENY",
            "</VirtualHost>",
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
        _safe_apache_config_without_security_headers(
            "<IfModule mod_headers.c>",
            "    Header always set X-Frame-Options DENY",
            "</IfModule>",
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
            "    Header always set X-Frame-Options DENY",
            "</If>",
            "<Else>",
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
        _safe_apache_config_without_security_headers(
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


def test_analyze_apache_config_ignores_header_inside_standalone_else_for_auditability(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
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
                "Listen 80",
                "Header always set X-Frame-Options DENY",
                "<Else>",
                "    Header always set X-Frame-Options ALLOW-FROM https://legacy.example.test",
                "</Else>",
            ]
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
            "    Header always set X-Frame-Options DENY",
            "</If>",
            "<Else>",
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


def test_analyze_apache_config_flags_identical_always_onsuccess_xfo_instances(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(
            "Header always set X-Frame-Options DENY",
            "Header onsuccess set X-Frame-Options DENY",
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
