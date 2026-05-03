from tests.nginx_helpers import (
    AnalysisResult,
    Path,
    _http_block,
    _line_number,
    _safe_server_block,
    analyze_nginx_config,
)


def test_analyze_nginx_config_reports_missing_access_log_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_access_log" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_access_log_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    access_log /var/log/nginx/access.log;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_access_log" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_access_log_when_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    access_log off;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_access_log" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_access_log_when_only_http_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    access_log /var/log/nginx/access.log;\n"
        "    server {\n"
        "        listen 80;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_access_log" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_log_format_when_custom_format_is_used(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    access_log /var/log/nginx/access.log main;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_log_format" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_log_format_for_default_format(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    access_log /var/log/nginx/access.log;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_log_format" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_log_format_when_named_format_is_defined(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        '    log_format main "$remote_addr";\n'
        "    server {\n"
        "        listen 80;\n"
        "        access_log /var/log/nginx/access.log main;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_log_format" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_log_format_when_log_format_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        '    log_format main "$remote_addr";\n'
        "    server {\n"
        "        listen 80;\n"
        "        access_log /var/log/nginx/access.log;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_log_format" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_log_format_when_access_log_is_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_log_format" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_log_format_when_only_log_format_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        'http {\n    log_format main "$remote_addr";\n}\n',
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_log_format" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_error_log_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_error_log" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_error_log_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    error_log /var/log/nginx/error.log warn;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_error_log" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_error_log_when_only_http_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    error_log /var/log/nginx/error.log warn;\n"
        "    server {\n"
        "        listen 80;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_error_log" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_hidden_files_deny_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_hidden_files_deny" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_hidden_files_deny_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    location ~ /\\. {\n        deny all;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_hidden_files_deny" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_hidden_files_deny_for_well_known_pattern(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location ~ /\\.(?!well-known) {\n"
        "        deny all;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_hidden_files_deny" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_hidden_files_deny_when_location_has_no_deny(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    location ~ /\\. {\n        return 404;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_hidden_files_deny" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_backup_file_deny_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        try_files $uri $uri/ =404;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_backup_file_deny" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_backup_file_deny_when_backup_extensions_are_denied(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location ~ \\.(bak|old|orig|save)$ {\n"
        "        deny all;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_backup_file_deny" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_backup_file_deny_when_trailing_tilde_is_denied(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location ~ ~$ {\n"
        "        deny all;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_backup_file_deny" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_backup_file_deny_when_location_returns_403(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location ~ \\.(bak|old|orig|save)$ {\n"
        "        return 403;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_backup_file_deny" for finding in result.findings
    )


def test_analyze_nginx_config_checks_backup_file_deny_per_server(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location ~ \\.(bak|old)$ { deny all; }\n"
        "}\n"
        "server {\n"
        "    listen 8080;\n"
        "    location / { try_files $uri =404; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    findings = [
        f for f in result.findings if f.rule_id == "nginx.missing_backup_file_deny"
    ]
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.line == 5


def test_analyze_nginx_config_reports_missing_content_security_policy_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_content_security_policy" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_content_security_policy_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    add_header Content-Security-Policy \"default-src 'self'\";\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_content_security_policy" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_content_security_policy_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        add_header Content-Security-Policy \"default-src 'self'\";\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_content_security_policy" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_http2_on_tls_listener(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = _http_block(
        _safe_server_block(
            "listen 127.0.0.1:443 ssl;",
            'add_header Strict-Transport-Security "max-age=31536000";',
            "ssl_certificate /etc/ssl/cert.pem;",
            "ssl_certificate_key /etc/ssl/key.pem;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            "ssl_prefer_server_ciphers on;",
            include_rate_limits=True,
        )
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.missing_http2_on_tls_listener"
    assert finding.title == "TLS listener missing http2 parameter"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == _line_number(config_text, "listen 127.0.0.1:443 ssl;")


def test_analyze_nginx_config_does_not_report_missing_http2_when_http2_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 443 ssl http2;",
            'add_header Strict-Transport-Security "max-age=31536000";',
            "ssl_certificate /etc/ssl/cert.pem;",
            "ssl_certificate_key /etc/ssl/key.pem;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            "ssl_prefer_server_ciphers on;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http2_on_tls_listener"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_http2_when_server_http2_on(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 443 ssl;",
            "http2 on;",
            'add_header Strict-Transport-Security "max-age=31536000";',
            "ssl_certificate /etc/ssl/cert.pem;",
            "ssl_certificate_key /etc/ssl/key.pem;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            "ssl_prefer_server_ciphers on;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http2_on_tls_listener"
        for finding in result.findings
    )


def test_analyze_nginx_config_inherits_http2_on_from_http_block(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            "http2 on;\n"
            + _safe_server_block(
                "listen 443 ssl;",
                'add_header Strict-Transport-Security "max-age=31536000";',
                "ssl_certificate /etc/ssl/cert.pem;",
                "ssl_certificate_key /etc/ssl/key.pem;",
                "ssl_ciphers HIGH:!aNULL:!MD5;",
                "ssl_prefer_server_ciphers on;",
                include_rate_limits=True,
            )
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http2_on_tls_listener"
        for finding in result.findings
    )


def test_analyze_nginx_config_uses_last_http2_directive_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            _safe_server_block(
                "listen 443 ssl;",
                "http2 on;",
                "http2 off;",
                'add_header Strict-Transport-Security "max-age=31536000";',
                "ssl_certificate /etc/ssl/cert.pem;",
                "ssl_certificate_key /etc/ssl/key.pem;",
                "ssl_ciphers HIGH:!aNULL:!MD5;",
                "ssl_prefer_server_ciphers on;",
                include_rate_limits=True,
            )
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_http2_on_tls_listener"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_http2_for_port_80_listener(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            _safe_server_block(
                "listen 127.0.0.1:80;",
                include_http_redirect=True,
                include_rate_limits=True,
            )
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_does_not_report_missing_http2_for_443_without_ssl(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(_safe_server_block("listen 127.0.0.1:443;", include_rate_limits=True)),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http2_on_tls_listener"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_protocols_with_tlsv1(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = _http_block(
        _safe_server_block(
            "ssl_protocols TLSv1 TLSv1.2;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            include_http_redirect=True,
            include_rate_limits=True,
        )
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.weak_ssl_protocols"
    assert finding.title == "Weak SSL/TLS protocols enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == _line_number(config_text, "ssl_protocols TLSv1 TLSv1.2;")


def test_analyze_nginx_config_reports_ssl_protocols_with_tlsv1_1(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = _http_block(
        _safe_server_block(
            "ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            include_http_redirect=True,
            include_rate_limits=True,
        )
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.weak_ssl_protocols"
    assert finding.title == "Weak SSL/TLS protocols enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == _line_number(
        config_text, "ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;"
    )


def test_analyze_nginx_config_does_not_report_ssl_protocols_with_modern_versions_only(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            _safe_server_block(
                "ssl_protocols TLSv1.2 TLSv1.3;",
                "ssl_ciphers HIGH:!aNULL:!MD5;",
                include_http_redirect=True,
                include_rate_limits=True,
            )
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_nginx_rule_pack_wiring_regression(tmp_path: Path) -> None:
    config = tmp_path / "nginx.conf"
    config.write_text(
        """
        http {
            server {
                listen 443 ssl;
                server_tokens on;
                ssl_protocols TLSv1 TLSv1.2;
                location / {
                    root html;
                }
            }
        }
        """.strip(),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config))
    assert isinstance(result, AnalysisResult)
    assert result.issues == []

    rule_ids = {finding.rule_id for finding in result.findings}

    assert {
        "nginx.server_tokens_on",
        "nginx.weak_ssl_protocols",
        "nginx.missing_hsts_header",
        "nginx.missing_access_log",
        "nginx.missing_server_name",
        "nginx.missing_ssl_certificate",
        "nginx.missing_ssl_ciphers",
    } <= rule_ids
