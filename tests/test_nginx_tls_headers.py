from tests.nginx_helpers import (
    AnalysisResult,
    Path,
    _http_block,
    _safe_server_block,
    analyze_nginx_config,
)


def test_analyze_nginx_config_reports_missing_ssl_ciphers_when_listen_uses_ssl(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            _safe_server_block(
                "listen 127.0.0.1:443 ssl http2;",
                "ssl_certificate cert.pem;",
                "ssl_certificate_key cert.key;",
                'add_header Strict-Transport-Security "max-age=31536000";',
                include_rate_limits=True,
            )
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.missing_ssl_ciphers"
    assert finding.title == "Missing ssl_ciphers directive"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 5


def test_analyze_nginx_config_reports_missing_ssl_ciphers_when_ssl_protocols_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            _safe_server_block(
                "ssl_protocols TLSv1.2 TLSv1.3;",
                include_http_redirect=True,
                include_rate_limits=True,
            )
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "nginx.missing_ssl_ciphers"


def test_analyze_nginx_config_does_not_treat_inherited_ssl_protocols_as_tls_intent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        "    server {\n"
        "        listen 80;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_ssl_ciphers" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_ssl_ciphers_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            _safe_server_block(
                "listen 127.0.0.1:443 ssl http2;",
                "ssl_certificate cert.pem;",
                "ssl_certificate_key cert.key;",
                "ssl_ciphers HIGH:!aNULL:!MD5;",
                "ssl_prefer_server_ciphers on;",
                'add_header Strict-Transport-Security "max-age=31536000";',
                include_rate_limits=True,
            )
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_does_not_report_missing_ssl_ciphers_when_inherited_from_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            "ssl_ciphers HIGH:!aNULL:!MD5;\nssl_prefer_server_ciphers on;",
            _safe_server_block(
                "listen 127.0.0.1:443 ssl http2;",
                "ssl_certificate cert.pem;",
                "ssl_certificate_key cert.key;",
                'add_header Strict-Transport-Security "max-age=31536000";',
                include_rate_limits=True,
            ),
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_ssl_ciphers" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_ssl_certificate_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_certificate" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_ssl_certificate_for_non_tls_server(
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
    assert not any(
        finding.rule_id == "nginx.missing_ssl_certificate" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_ssl_certificate_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    location / {\n"
        "        ssl_certificate cert.pem;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_ssl_certificate" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_ssl_certificate_key_when_ssl_certificate_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_certificate_key" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_ssl_certificate_key_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_certificate_key" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_ssl_certificate_key_for_non_tls_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    ssl_certificate cert.pem;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_certificate_key" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_ssl_certificate_key_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    location / {\n"
        "        ssl_certificate_key cert.key;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_certificate_key" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_ssl_prefer_server_ciphers_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_ssl_prefer_server_ciphers_when_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers off;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_ssl_prefer_server_ciphers_when_on(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_ssl_prefer_server_ciphers_for_non_tls_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    ssl_ciphers HIGH:!aNULL:!MD5;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_ssl_prefer_server_ciphers_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    location / {\n"
        "        ssl_prefer_server_ciphers on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers" for finding in result.findings
    )


def test_analyze_nginx_config_inherits_ssl_prefer_server_ciphers_from_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers"
        for finding in result.findings
    )


def test_analyze_nginx_config_checks_inherited_ssl_ciphers_for_prefer_server_ciphers(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers"
        for finding in result.findings
    )


def test_analyze_nginx_config_uses_last_ssl_prefer_server_ciphers_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_prefer_server_ciphers off;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_without_verify_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_without_verify_when_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify off;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_ssl_stapling_without_verify_when_on(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_uses_last_ssl_stapling_verify_value(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify off;\n"
        "    ssl_stapling_verify on;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_ssl_stapling_without_verify_for_non_tls_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    ssl_stapling on;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_without_verify_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    resolver 1.1.1.1;\n"
        "    location / {\n"
        "        ssl_stapling_verify on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_inherits_ssl_stapling_for_verify_check(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    ssl_stapling on;\n"
        "    resolver 1.1.1.1;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "        ssl_prefer_server_ciphers on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_without_verify"
        for finding in result.findings
    )


def test_analyze_nginx_config_inherits_ssl_stapling_verify_on(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "    resolver 1.1.1.1;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "        ssl_prefer_server_ciphers on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_without_verify"
        for finding in result.findings
    )


def test_analyze_nginx_config_server_stapling_inherits_ssl_stapling_verify_on(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    ssl_stapling_verify on;\n"
        "    resolver 1.1.1.1;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "        ssl_prefer_server_ciphers on;\n"
        "        ssl_stapling on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_without_verify"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_missing_resolver_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_ssl_stapling_missing_resolver_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_ssl_stapling_missing_resolver_for_non_tls_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    ssl_stapling on;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_missing_resolver_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "    location / {\n"
        "        resolver 1.1.1.1;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver" for finding in result.findings
    )


def test_analyze_nginx_config_inherits_ssl_stapling_for_resolver_check(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    ssl_stapling on;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "        ssl_prefer_server_ciphers on;\n"
        "        ssl_stapling_verify on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver"
        for finding in result.findings
    )


def test_analyze_nginx_config_inherits_resolver_for_stapling_check(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    resolver 1.1.1.1;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "        ssl_prefer_server_ciphers on;\n"
        "        ssl_stapling on;\n"
        "        ssl_stapling_verify on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver"
        for finding in result.findings
    )


def test_analyze_nginx_config_uses_last_ssl_stapling_value_for_resolver_check(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling off;\n"
        "    ssl_stapling_verify on;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_disabled_when_directive_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_disabled" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_disabled_when_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_stapling off;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_disabled" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_ssl_stapling_disabled_when_on(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_disabled" for finding in result.findings
    )


def test_analyze_nginx_config_inherits_ssl_stapling_on_from_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    ssl_stapling on;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        ssl_stapling_verify on;\n"
        "        resolver 1.1.1.1;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_disabled" for finding in result.findings
    )


def test_analyze_nginx_config_reports_server_override_of_http_ssl_stapling(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    ssl_stapling on;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        ssl_stapling off;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_disabled" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_disabled_when_inherited_off_from_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    ssl_stapling off;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_disabled" for finding in result.findings
    )


def test_analyze_nginx_config_uses_last_ssl_stapling_value(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_stapling off;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_disabled" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_ssl_stapling_disabled_for_non_tls_server(
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
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_disabled" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_disabled_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    location / {\n"
        "        ssl_stapling on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_disabled" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_hsts_header_for_tls_server(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_hsts_header" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_hsts_header_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        '    add_header Strict-Transport-Security "max-age=31536000";\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_hsts_header" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_hsts_header_for_non_tls_server(
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
    assert not any(finding.rule_id == "nginx.missing_hsts_header" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_hsts_header_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    location / {\n"
        '        add_header Strict-Transport-Security "max-age=31536000";\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_hsts_header" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_x_content_type_options_when_missing(
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
        finding.rule_id == "nginx.missing_x_content_type_options" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_x_content_type_options_when_wrong_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header X-Content-Type-Options off;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_x_content_type_options" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_x_content_type_options_when_nosniff(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header X-Content-Type-Options nosniff;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_content_type_options" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_x_content_type_options_when_inherited_from_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    add_header X-Content-Type-Options nosniff;\n"
        "    server {\n"
        "        listen 80;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_content_type_options" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_x_content_type_options_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        add_header X-Content-Type-Options nosniff;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_x_content_type_options" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_x_frame_options_when_missing(
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
    assert any(finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_x_frame_options_when_wrong_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header X-Frame-Options off;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_x_frame_options_when_deny(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header X-Frame-Options DENY;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings
    )


def test_analyze_nginx_config_matches_security_headers_case_insensitively(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header x-frame-options DENY;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_x_frame_options_when_sameorigin(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header X-Frame-Options SAMEORIGIN;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_x_frame_options_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        add_header X-Frame-Options DENY;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_x_xss_protection_when_missing(
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
    assert any(finding.rule_id == "nginx.missing_x_xss_protection" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_x_xss_protection_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        'server {\n    listen 80;\n    add_header X-XSS-Protection "1; mode=block";\n}\n',
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_xss_protection" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_x_xss_protection_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        '        add_header X-XSS-Protection "1; mode=block";\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_x_xss_protection" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_server_name_when_missing(
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
    assert any(finding.rule_id == "nginx.missing_server_name" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_server_name_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    server_name example.com;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_server_name" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_server_name_with_multiple_values(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    server_name example.com www.example.com;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_server_name" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_referrer_policy_when_missing(
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
    assert any(finding.rule_id == "nginx.missing_referrer_policy" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_referrer_policy_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header Referrer-Policy no-referrer;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_referrer_policy" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_referrer_policy_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        add_header Referrer-Policy no-referrer;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_referrer_policy" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_permissions_policy_when_missing(
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
    assert any(finding.rule_id == "nginx.missing_permissions_policy" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_permissions_policy_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header Permissions-Policy geolocation=();\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_permissions_policy" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_permissions_policy_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        add_header Permissions-Policy geolocation=();\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_permissions_policy" for finding in result.findings)
