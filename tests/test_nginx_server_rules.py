from tests.nginx_helpers import (
    AnalysisResult,
    Path,
    _http_block,
    _line_number,
    _safe_server_block,
    analyze_nginx_config,
    pytest,
)


@pytest.mark.parametrize(
    ("config_text", "expected_rule_id"),
    [
        pytest.param(
            "server {\n"
            "    listen 80 default_server;\n"
            "    server_name _;\n"
            "}\n",
            "nginx.default_server_not_rejecting_unknown_hosts",
            id="default-server-does-not-reject",
        ),
        pytest.param(
            "http {\n"
            "    log_format main \"$remote_addr\";\n"
            "    server {\n"
            "        listen 80;\n"
            "        access_log /var/log/nginx/access.log main;\n"
            "    }\n"
            "}\n",
            "nginx.log_format_missing_fields",
            id="log-format-missing-fields",
        ),
        pytest.param(
            "http {\n"
            "    log_format main \"$time_iso8601 $remote_addr $remote_user $request_time $status $http_user_agent\";\n"
            "    server {\n"
            "        listen 80;\n"
            "        access_log /var/log/nginx/access.log main;\n"
            "    }\n"
            "}\n",
            "nginx.log_format_missing_fields",
            id="log-format-does-not-substring-match-request",
        ),
        pytest.param(
            "server {\n"
            "    listen 80;\n"
            "    error_log /dev/null crit;\n"
            "}\n",
            "nginx.error_log_too_restrictive",
            id="error-log-too-restrictive",
        ),
        pytest.param(
            "server {\n"
            "    listen 80;\n"
            "    location / {\n"
            "        proxy_pass http://backend;\n"
            "    }\n"
            "}\n",
            "nginx.proxy_missing_source_ip_headers",
            id="proxy-missing-source-headers",
        ),
        pytest.param(
            "server {\n"
            "    listen 80;\n"
            "    server_name example.com;\n"
            "}\n",
            "nginx.missing_http_to_https_redirect",
            id="missing-http-to-https-redirect",
        ),
        pytest.param(
            "server {\n"
            "    server_name example.com;\n"
            "}\n",
            "nginx.missing_http_to_https_redirect",
            id="named-server-without-listen-defaults-to-http",
        ),
        pytest.param(
            "server {\n"
            "    listen 127.0.0.1;\n"
            "    server_name example.com;\n"
            "}\n",
            "nginx.missing_http_to_https_redirect",
            id="implicit-http-address-listen",
        ),
        pytest.param(
            "server {\n"
            "    listen 80;\n"
            "    add_header Content-Security-Policy \"default-src 'self'; script-src 'unsafe-inline'\";\n"
            "}\n",
            "nginx.content_security_policy_unsafe",
            id="unsafe-csp",
        ),
        pytest.param(
            "server {\n"
            "    listen 80;\n"
            "    add_header Content-Security-Policy \"default-src-elem 'self'; frame-ancestors 'self'\" always;\n"
            "}\n",
            "nginx.content_security_policy_unsafe",
            id="csp-does-not-substring-match-default-src-elem",
        ),
        pytest.param(
            "server {\n"
            "    listen 80;\n"
            "    add_header Referrer-Policy unsafe-url always;\n"
            "}\n",
            "nginx.referrer_policy_unsafe",
            id="unsafe-referrer-policy",
        ),
        pytest.param(
            "server {\n"
            "    listen 80;\n"
            "    add_header Referrer-Policy no-referrer;\n"
            "}\n",
            "nginx.referrer_policy_unsafe",
            id="referrer-policy-missing-always",
        ),
    ],
)
def test_analyze_nginx_config_reports_cis_policy_control_findings(
    tmp_path: Path,
    config_text: str,
    expected_rule_id: str,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(finding.rule_id == expected_rule_id for finding in result.findings)


def test_analyze_nginx_config_accepts_cis_policy_control_baseline(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    log_format main \"$time_iso8601 $remote_addr $remote_user $request $status $http_user_agent\";\n"
        "    server {\n"
        "        listen 80 default_server;\n"
        "        server_name _;\n"
        "        return 444;\n"
        "    }\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name example.com;\n"
        "        return 301 https://$host$request_uri;\n"
        "        error_log /var/log/nginx/error.log notice;\n"
        "        access_log /var/log/nginx/access.log main;\n"
        "        add_header Content-Security-Policy \"default-src 'self'; form-action 'self'; frame-ancestors 'self'\" always;\n"
        "        add_header Referrer-Policy strict-origin-when-cross-origin always;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-Proto $scheme;\n"
        "        location / {\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))
    new_rule_ids = {
        "nginx.content_security_policy_unsafe",
        "nginx.default_server_not_rejecting_unknown_hosts",
        "nginx.error_log_too_restrictive",
        "nginx.log_format_missing_fields",
        "nginx.missing_http_to_https_redirect",
        "nginx.proxy_missing_source_ip_headers",
        "nginx.referrer_policy_unsafe",
    }

    assert result.issues == []
    assert not (new_rule_ids & {finding.rule_id for finding in result.findings})


def test_analyze_nginx_config_ignores_unused_short_log_format(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    log_format main \"$time_iso8601 $remote_addr $remote_user $request $status $http_user_agent\";\n"
        "    log_format debug \"$remote_addr\";\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name example.com;\n"
        "        return 301 https://$host$request_uri;\n"
        "        access_log /var/log/nginx/access.log main;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.log_format_missing_fields"
        for finding in result.findings
    )


def test_analyze_nginx_config_ignores_access_log_gzip_option_as_format_name(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    log_format main \"$time_iso8601 $remote_addr $remote_user $request $status $http_user_agent\";\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name example.com;\n"
        "        return 301 https://$host$request_uri;\n"
        "        access_log /var/log/nginx/access.log gzip=5;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.log_format_missing_fields"
        for finding in result.findings
    )


def test_analyze_nginx_config_accepts_short_https_return_redirect(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name example.com;\n"
        "    return https://example.com$request_uri;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http_to_https_redirect"
        for finding in result.findings
    )


def test_analyze_nginx_config_rejects_relative_redirect_with_https_query(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name example.com;\n"
        "    return 301 /login?next=https://idp.example;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_http_to_https_redirect"
        for finding in result.findings
    )


def test_analyze_nginx_config_ignores_non_http_listen_with_socket_option(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 8080 reuseport;\n"
        "    server_name example.com;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http_to_https_redirect"
        for finding in result.findings
    )


def test_analyze_nginx_config_accepts_normalized_proxy_source_headers(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    proxy_set_header X-Forwarded-For \"$PROXY_ADD_X_FORWARDED_FOR\";\n"
        "    proxy_set_header X-Real-IP '$REMOTE_ADDR';\n"
        "    proxy_set_header X-Forwarded-Proto \"$SCHEME\";\n"
        "    location / {\n"
        "        proxy_pass http://backend;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.proxy_missing_source_ip_headers"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_duplicate_listen_in_same_server(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = _http_block(
        _safe_server_block(
            "listen 80;",
            "listen 80;",
            include_http_redirect=True,
            include_rate_limits=True,
        )
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1

    finding = server_findings[0]
    assert finding.rule_id == "nginx.duplicate_listen"
    assert finding.title == "Duplicate listen directive"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == _line_number(config_text, "listen 80;", occurrence=2)


def test_analyze_nginx_config_does_not_report_when_listen_values_differ(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            _safe_server_block(
                "listen 80;",
                "listen 443;",
                include_http_redirect=True,
                include_rate_limits=True,
            )
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert server_findings == []


def test_analyze_nginx_config_reports_server_tokens_on(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("http {\n    server_tokens on;\n}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.server_tokens_on"
    assert finding.title == "Server tokens enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_nginx_config_does_not_report_server_tokens_off(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("http {\n    server_tokens off;\n}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_autoindex_on(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("location /listing/ {\n    autoindex on;\n}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.autoindex_on"
    assert finding.title == "Autoindex enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_nginx_config_does_not_report_autoindex_off(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("location /listing/ {\n    autoindex off;\n}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_alias_without_trailing_slash(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location /static/ {\n    alias /srv/static;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.alias_without_trailing_slash"
    assert finding.title == "Alias path missing trailing slash"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_nginx_config_does_not_report_alias_with_trailing_slash(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location /static/ {\n    alias /srv/static/;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_executable_scripts_allowed_in_uploads(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = _safe_server_block(
        "listen 80;",
        "location /uploads {",
        "    root /srv/www;",
        "}",
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []

    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
    )
    assert finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
    assert finding.title == "Executable scripts allowed in upload-like location"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == _line_number(config_text, "location /uploads {")


def test_analyze_nginx_config_does_not_report_executable_scripts_in_uploads_when_php_is_blocked(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /uploads {",
            "    root /srv/www;",
            "    location ~ \\.php$ {",
            "        return 403;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_executable_scripts_in_uploads_when_scripts_are_denied(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /files {",
            "    root /srv/www;",
            "    location ~ \\.sh$ {",
            "        deny all;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_respects_sibling_upload_script_deny(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /uploads {",
            "    root /srv/www;",
            "}",
            "location ~ ^/uploads/.*\\.php$ {",
            "    deny all;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_executable_scripts_for_root_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location / {",
            "    root /srv/www;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_executable_scripts_allowed_in_media_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /media {",
            "    root /srv/www;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_http_method_restrictions_for_admin(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_http_method_restrictions_when_limit_except_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    proxy_pass http://backend;",
            "    limit_except GET POST {",
            "        deny all;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_http_method_restrictions_for_root_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location / {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_http_method_restrictions_for_api(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /api {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_access_restrictions_on_admin_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_access_restrictions_when_allow_and_deny_are_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    allow 10.0.0.0/8;",
            "    deny all;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_access_restrictions_when_auth_basic_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            '    auth_basic "Restricted";',
            "    auth_basic_user_file /etc/nginx/.htpasswd;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_access_restrictions_when_auth_basic_is_inherited(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            'auth_basic "Restricted";',
            "auth_basic_user_file /etc/nginx/.htpasswd;",
            "location /admin {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_access_restrictions_when_allow_all_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    allow all;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_access_restrictions_when_auth_basic_is_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    auth_basic off;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_sensitive_location_missing_ip_filter_with_auth_basic(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = _safe_server_block(
        "listen 80;",
        "location /admin {",
        '    auth_basic "Restricted";',
        "    auth_basic_user_file /etc/nginx/.htpasswd;",
        "}",
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "nginx.sensitive_location_missing_ip_filter"
    )
    assert finding.title == "Sensitive location lacks an IP allow/deny filter"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == _line_number(config_text, "location /admin {")


def test_analyze_nginx_config_reports_sensitive_location_missing_ip_filter_with_specific_deny(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    deny 10.0.0.0/8;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.sensitive_location_missing_ip_filter"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_sensitive_location_missing_ip_filter_without_access_restriction(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )
    assert not any(
        finding.rule_id == "nginx.sensitive_location_missing_ip_filter"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_sensitive_location_missing_ip_filter_when_allowlist_denies_all(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    allow 10.0.0.0/8;",
            "    deny all;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.sensitive_location_missing_ip_filter"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_sensitive_location_missing_ip_filter_when_deny_all(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /internal {",
            "    deny all;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.sensitive_location_missing_ip_filter"
        for finding in result.findings
    )


def test_analyze_nginx_config_inherits_sensitive_location_ip_filter_from_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "allow 10.0.0.0/8;",
            "deny all;",
            "location /admin {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.sensitive_location_missing_ip_filter"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_sensitive_location_ip_filter_bypassed_by_satisfy_any(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "allow 10.0.0.0/8;",
            "deny all;",
            "location /admin {",
            "    satisfy any;",
            '    auth_basic "Restricted";',
            "    auth_basic_user_file /etc/nginx/.htpasswd;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.sensitive_location_missing_ip_filter"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_auth_basic_user_file_in_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /protected {",
            '    auth_basic "Restricted";',
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_auth_basic_user_file" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_auth_basic_user_file_in_location_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /protected {",
            '    auth_basic "Restricted";',
            "    auth_basic_user_file /etc/nginx/.htpasswd;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_auth_basic_user_file" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_auth_basic_user_file_in_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            'auth_basic "Restricted";',
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_auth_basic_user_file" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_auth_basic_user_file_when_auth_basic_is_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /protected {",
            "    return 204;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_auth_basic_user_file" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_access_restrictions_for_root_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location / {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_allowed_methods_restriction_for_uploads(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /uploads {",
            "    root /srv/www;",
            "    location ~ \\.php$ {",
            "        return 403;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_allowed_methods_restriction_for_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_allowed_methods_restriction_for_uploads_when_limit_except_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /uploads {",
            "    root /srv/www;",
            "    location ~ \\.php$ {",
            "        return 403;",
            "    }",
            "    limit_except GET POST {",
            "        deny all;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_allowed_methods_restriction_for_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_http_method_policy_allows_unapproved_method(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = _safe_server_block(
        "listen 80;",
        "location /api {",
        "    proxy_pass http://backend;",
        "    limit_except GET POST DELETE {",
        "        deny all;",
        "    }",
        "}",
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "nginx.http_method_policy_allows_unapproved"
    )
    assert finding.title == "HTTP method policy allows unapproved methods"
    assert "DELETE" in finding.description
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == _line_number(config_text, "limit_except GET POST DELETE {")


def test_analyze_nginx_config_does_not_report_http_method_policy_for_approved_methods(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /api {",
            "    proxy_pass http://backend;",
            "    limit_except GET POST OPTIONS {",
            "        deny all;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.http_method_policy_allows_unapproved"
        for finding in result.findings
    )


def test_analyze_nginx_config_normalizes_http_method_policy_case(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /api {",
            "    proxy_pass http://backend;",
            "    limit_except get post options {",
            "        deny all;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.http_method_policy_allows_unapproved"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_allowed_methods_restriction_for_root_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location / {",
            "    root /srv/www;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_allowed_methods_restriction_for_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_allowed_methods_restriction_for_files(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /files {",
            "    root /srv/www;",
            "    location ~ \\.sh$ {",
            "        deny all;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_allowed_methods_restriction_for_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_allow_all_with_deny_all_in_same_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location /protected/ {\n    allow all;\n    deny all;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.allow_all_with_deny_all"
    assert finding.title == "Conflicting allow/deny all directives"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 1


def test_analyze_nginx_config_does_not_report_when_only_one_access_rule_targets_all(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location /protected/ {\n    allow all;\n    deny 10.0.0.0/8;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_if_inside_location(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = _safe_server_block(
        "location /app {",
        "    if ($deny) {",
        "        return 403;",
        "    }",
        "}",
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []

    finding = next(
        finding for finding in result.findings if finding.rule_id == "nginx.if_in_location"
    )
    assert finding.rule_id == "nginx.if_in_location"
    assert finding.title == "if inside location block"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == _line_number(config_text, "if ($deny) {")


def test_analyze_nginx_config_does_not_report_if_outside_location(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "if ($deny) {",
            "    return 403;",
            "}",
            "location /app {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.if_in_location" for finding in result.findings
    )
