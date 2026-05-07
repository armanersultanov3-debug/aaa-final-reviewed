from tests.nginx_helpers import (
    AnalysisResult,
    Path,
    _safe_server_block,
    analyze_nginx_config,
    pytest,
)
from webconf_audit.models import Finding


def _finding_by_rule_id(result: AnalysisResult, rule_id: str) -> Finding:
    matches = [finding for finding in result.findings if finding.rule_id == rule_id]
    if not matches:
        raise AssertionError(f"Missing expected finding {rule_id!r}")
    if len(matches) > 1:
        raise AssertionError(
            f"Expected exactly one finding for {rule_id!r}, got {len(matches)}"
        )
    return matches[0]


def test_analyze_nginx_config_reports_missing_client_max_body_size_when_missing(
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
        finding.rule_id == "nginx.missing_client_max_body_size" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_max_body_size_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_max_body_size 10m;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_max_body_size" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_client_body_timeout_when_missing(
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
        finding.rule_id == "nginx.missing_client_body_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_body_timeout_when_10s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_body_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_body_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_body_timeout_when_60s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_body_timeout 60s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_body_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_body_timeout_when_declared_in_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    client_body_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_body_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_client_header_timeout_when_missing(
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
        finding.rule_id == "nginx.missing_client_header_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_header_timeout_when_10s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_header_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_header_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_header_timeout_when_60s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_header_timeout 60s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_header_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_header_timeout_when_declared_in_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    client_header_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_header_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_send_timeout_when_missing(
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
    assert any(finding.rule_id == "nginx.missing_send_timeout" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_send_timeout_when_10s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    send_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_send_timeout" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_send_timeout_when_60s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    send_timeout 60s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_send_timeout" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_send_timeout_when_declared_in_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    send_timeout 10s;\n    server {\n        listen 80;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_send_timeout" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_keepalive_timeout_when_missing(
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
        finding.rule_id == "nginx.missing_keepalive_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_keepalive_timeout_when_10s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    keepalive_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_keepalive_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_keepalive_timeout_when_60s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    keepalive_timeout 60s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_keepalive_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_keepalive_timeout_when_declared_in_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    keepalive_timeout 10s;\n    server {\n        listen 80;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_keepalive_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_client_max_body_size_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    location / {\n        client_max_body_size 10m;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_client_max_body_size" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_max_body_size_when_http_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    client_max_body_size 10m;\n    server {\n        listen 80;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_max_body_size" for finding in result.findings
    )


_TIMEOUT_RULE_IDS = frozenset(
    {
        "nginx.client_body_timeout_too_high",
        "nginx.client_header_timeout_too_high",
        "nginx.send_timeout_too_high",
        "nginx.keepalive_timeout_too_high",
    }
)


@pytest.mark.parametrize(
    ("config", "expected_present", "expected_absent"),
    [
        pytest.param(
            "http {\n"
            "    client_body_timeout 60s;\n"
            "    client_header_timeout 25s;\n"
            "    send_timeout 60s;\n"
            "    keepalive_timeout 65s;\n"
            "    server {\n"
            "        listen 80;\n"
            "    }\n"
            "}\n",
            _TIMEOUT_RULE_IDS,
            frozenset(),
            id="above-cis-limits-in-http",
        ),
        pytest.param(
            "server {\n"
            "    listen 80;\n"
            "    client_body_timeout 0;\n"
            "    client_header_timeout 0s;\n"
            "    send_timeout 0;\n"
            "    keepalive_timeout 0;\n"
            "}\n",
            _TIMEOUT_RULE_IDS,
            frozenset(),
            id="zero-values-in-server",
        ),
        pytest.param(
            "server {\n"
            "    listen 80;\n"
            "    client_body_timeout 20s;\n"
            "    client_header_timeout 20s;\n"
            "    send_timeout 10s;\n"
            "    keepalive_timeout 10s;\n"
            "}\n",
            frozenset(),
            _TIMEOUT_RULE_IDS,
            id="at-cis-limits-in-server",
        ),
    ],
)
def test_analyze_nginx_config_timeout_value_matrix(
    tmp_path: Path,
    config: str,
    expected_present: frozenset[str],
    expected_absent: frozenset[str],
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    rule_ids = {finding.rule_id for finding in result.findings}
    assert expected_present <= rule_ids
    assert rule_ids.isdisjoint(expected_absent)


def test_analyze_nginx_config_ignores_high_client_body_timeout_inside_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    client_body_timeout 10s;\n"
        "    location /upload {\n"
        "        client_body_timeout 300s;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.client_body_timeout_too_high"
        for finding in result.findings
    )


def test_analyze_nginx_config_ignores_high_client_header_timeout_inside_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    client_header_timeout 10s;\n"
        "    location /api {\n"
        "        client_header_timeout 300s;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.client_header_timeout_too_high"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_high_keepalive_timeout_inside_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    keepalive_timeout 10s;\n"
        "    location /api {\n"
        "        keepalive_timeout 120s;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.keepalive_timeout_too_high"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_high_send_timeout_inside_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    send_timeout 10s;\n"
        "    location /stream {\n"
        "        send_timeout 300s;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.send_timeout_too_high"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_unlimited_client_max_body_size(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_max_body_size 0;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.client_max_body_size_unlimited"
        for finding in result.findings
    )


def test_analyze_nginx_config_accepts_nonzero_client_max_body_size(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_max_body_size 2m;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.client_max_body_size_unlimited"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_disabled_ssl_session_tickets(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 443 ssl;",
            "ssl_certificate cert.pem;",
            "ssl_certificate_key cert.key;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            "ssl_prefer_server_ciphers on;",
            "ssl_session_tickets off;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_session_tickets_disabled"
        for finding in result.findings
    )


def test_analyze_nginx_config_accepts_enabled_ssl_session_tickets(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 443 ssl;",
            "ssl_certificate cert.pem;",
            "ssl_certificate_key cert.key;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            "ssl_prefer_server_ciphers on;",
            "ssl_session_tickets on;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_session_tickets_disabled"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_restrictive_large_client_header_buffers(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    large_client_header_buffers 2 1k;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.large_client_header_buffers_too_restrictive"
        for finding in result.findings
    )


def test_analyze_nginx_config_accepts_default_large_client_header_buffers(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    large_client_header_buffers 4 8k;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.large_client_header_buffers_too_restrictive"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_limit_req_when_missing(
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
    assert any(finding.rule_id == "nginx.missing_limit_req" for finding in result.findings)


def test_analyze_nginx_config_keeps_missing_limit_req_low_without_public_autoindex(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    finding = _finding_by_rule_id(result, "nginx.missing_limit_req")
    assert finding.severity == "low"
    assert "severity_reason" not in finding.metadata


def test_analyze_nginx_config_raises_missing_limit_req_to_medium_for_public_autoindex(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_conn addr 10;\n"
        "        location /files/ {\n"
        "            autoindex on;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    finding = _finding_by_rule_id(result, "nginx.missing_limit_req")
    assert finding.severity == "medium"
    assert finding.metadata["severity_reason"] == "public_autoindex_without_request_limits"


def test_analyze_nginx_config_raises_missing_limit_req_to_medium_for_server_autoindex(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        autoindex on;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    finding = _finding_by_rule_id(result, "nginx.missing_limit_req")
    assert finding.severity == "medium"
    assert finding.metadata["severity_reason"] == "public_autoindex_without_request_limits"


def test_analyze_nginx_config_keeps_missing_limit_req_low_for_internal_autoindex(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_conn addr 10;\n"
        "        location /private-files/ {\n"
        "            internal;\n"
        "            autoindex on;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    finding = _finding_by_rule_id(result, "nginx.missing_limit_req")
    assert finding.severity == "low"
    assert "severity_reason" not in finding.metadata


def test_analyze_nginx_config_reports_missing_limit_conn_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req zone=perip burst=10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_limit_conn" for finding in result.findings)


def test_analyze_nginx_config_keeps_missing_limit_conn_low_without_public_autoindex(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req zone=perip burst=10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    finding = _finding_by_rule_id(result, "nginx.missing_limit_conn")
    assert finding.severity == "low"
    assert "severity_reason" not in finding.metadata


def test_analyze_nginx_config_raises_missing_limit_conn_to_medium_for_public_autoindex(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req zone=perip burst=10;\n"
        "        location /files/ {\n"
        "            autoindex on;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    finding = _finding_by_rule_id(result, "nginx.missing_limit_conn")
    assert finding.severity == "medium"
    assert finding.metadata["severity_reason"] == "public_autoindex_without_request_limits"


def test_analyze_nginx_config_raises_missing_limit_conn_to_medium_for_server_autoindex(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    server {\n"
        "        listen 80;\n"
        "        autoindex on;\n"
        "        limit_req zone=perip burst=10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    finding = _finding_by_rule_id(result, "nginx.missing_limit_conn")
    assert finding.severity == "medium"
    assert finding.metadata["severity_reason"] == "public_autoindex_without_request_limits"


def test_analyze_nginx_config_keeps_missing_limit_conn_low_for_internal_autoindex(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req zone=perip burst=10;\n"
        "        location /private-files/ {\n"
        "            internal;\n"
        "            autoindex on;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    finding = _finding_by_rule_id(result, "nginx.missing_limit_conn")
    assert finding.severity == "low"
    assert "severity_reason" not in finding.metadata


def test_analyze_nginx_config_does_not_report_missing_limit_conn_when_present_in_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req zone=perip burst=10;\n    limit_conn addr 10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_conn_when_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    limit_req zone=perip burst=10;\n"
        "    location / {\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_limit_conn_when_only_limit_req_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req zone=perip burst=10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_limit_conn" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_limit_req_zone_when_limit_req_is_used(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req zone=perip burst=10;\n    limit_conn addr 10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_limit_req_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_req_zone_when_limit_req_zone_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req zone=perip burst=10;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_req_zone_when_limit_req_is_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_conn addr 10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_req_zone_when_only_limit_req_zone_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req_zone" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_limit_conn_zone_when_limit_conn_is_used(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n    limit_req zone=perip burst=10;\n    limit_conn addr 10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_limit_conn_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_conn_zone_when_limit_conn_zone_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req zone=perip burst=10;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn_zone" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_limit_conn_zone_for_mismatched_zone(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_conn_zone $binary_remote_addr zone=perip:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(f.rule_id == "nginx.missing_limit_conn_zone" for f in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_conn_zone_when_limit_conn_is_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n    limit_req zone=perip burst=10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_conn_zone_when_only_limit_conn_zone_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "        limit_req zone=perip burst=10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn_zone" for finding in result.findings)


@pytest.mark.parametrize(
    ("config_text", "expected_rule_id"),
    [
        pytest.param(
            "http {\n"
            "    limit_conn_zone $server_name zone=addr:10m;\n"
            "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
            "    server {\n"
            "        listen 80;\n"
            "        limit_req zone=perip burst=10;\n"
            "        limit_conn addr 10;\n"
            "    }\n"
            "}\n",
            "nginx.limit_conn_zone_not_per_ip",
            id="limit-conn-zone-not-per-ip",
        ),
        pytest.param(
            "http {\n"
            "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
            "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
            "    server {\n"
            "        listen 80;\n"
            "        limit_req zone=perip burst=10;\n"
            "        limit_conn addr 0;\n"
            "    }\n"
            "}\n",
            "nginx.limit_conn_invalid_limit",
            id="limit-conn-invalid-limit",
        ),
        pytest.param(
            "http {\n"
            "    limit_req_zone $server_name zone=perip:10m rate=10r/s;\n"
            "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
            "    server {\n"
            "        listen 80;\n"
            "        limit_req zone=perip burst=10;\n"
            "        limit_conn addr 10;\n"
            "    }\n"
            "}\n",
            "nginx.limit_req_zone_not_per_ip",
            id="limit-req-zone-not-per-ip",
        ),
        pytest.param(
            "http {\n"
            "    limit_req_zone $binary_remote_addr zone=perip:10m rate=0r/s;\n"
            "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
            "    server {\n"
            "        listen 80;\n"
            "        limit_req zone=perip burst=10;\n"
            "        limit_conn addr 10;\n"
            "    }\n"
            "}\n",
            "nginx.limit_req_zone_invalid_rate",
            id="limit-req-zone-zero-rate",
        ),
        pytest.param(
            "http {\n"
            "    limit_req_zone $binary_remote_addr zone=perip:10m;\n"
            "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
            "    server {\n"
            "        listen 80;\n"
            "        limit_req zone=perip burst=10;\n"
            "        limit_conn addr 10;\n"
            "    }\n"
            "}\n",
            "nginx.limit_req_zone_invalid_rate",
            id="limit-req-zone-missing-rate",
        ),
        pytest.param(
            "http {\n"
            "    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/s;\n"
            "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
            "    server {\n"
            "        listen 80;\n"
            "        limit_req zone=perip burst=10;\n"
            "        limit_conn addr 10;\n"
            "    }\n"
            "}\n",
            "nginx.limit_req_unknown_zone",
            id="limit-req-unknown-zone",
        ),
    ],
)
def test_analyze_nginx_config_reports_limit_quality_findings(
    tmp_path: Path,
    config_text: str,
    expected_rule_id: str,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        config_text,
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(f.rule_id == expected_rule_id for f in result.findings)


def test_analyze_nginx_config_accepts_per_ip_limit_quality_controls(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $remote_addr zone=perip:10m rate=30r/m;\n"
        "    limit_conn_zone $remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req zone=perip burst=10;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))
    new_rule_ids = {
        "nginx.limit_conn_invalid_limit",
        "nginx.limit_conn_zone_not_per_ip",
        "nginx.limit_req_unknown_zone",
        "nginx.limit_req_zone_invalid_rate",
        "nginx.limit_req_zone_not_per_ip",
    }

    assert result.issues == []
    assert not (new_rule_ids & {finding.rule_id for finding in result.findings})


def test_analyze_nginx_config_does_not_report_missing_limit_req_when_present_in_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req zone=perip burst=10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_req_when_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location /api {\n"
        "        limit_req zone=perip burst=10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_req_when_inherited_from_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    limit_req zone=perip burst=10;\n    server {\n        listen 80;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_conn_when_inherited_from_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    limit_conn addr 10;\n    server {\n        listen 80;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn" for finding in result.findings)


def test_analyze_nginx_config_reports_public_autoindex_with_sibling_rate_limits(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        location /api/ {\n"
        "            limit_req zone=perip burst=10;\n"
        "            limit_conn addr 10;\n"
        "            proxy_pass http://api.internal;\n"
        "        }\n"
        "        location /downloads/ {\n"
        "            autoindex on;\n"
        "            root /srv/www;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    finding = _finding_by_rule_id(result, "nginx.public_autoindex_rate_limit_policy_weak")
    assert finding.location is not None
    assert finding.location.line == 12
    assert finding.metadata["weaknesses"] == "limit_req_not_effective,limit_conn_not_effective"


def test_analyze_nginx_config_reports_public_autoindex_weak_rate_limit_values(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=1000r/s;\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req zone=perip burst=1000;\n"
        "        limit_conn addr 500;\n"
        "        location /downloads/ {\n"
        "            autoindex on;\n"
        "            root /srv/www;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    finding = _finding_by_rule_id(result, "nginx.public_autoindex_rate_limit_policy_weak")
    assert finding.location is not None
    assert finding.location.line == 9
    assert finding.metadata["weaknesses"] == "limit_req_rate_too_high,limit_conn_limit_too_high"


def test_analyze_nginx_config_accepts_public_autoindex_moderate_rate_limits(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=30r/m;\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req zone=perip burst=10;\n"
        "        limit_conn addr 10;\n"
        "        location /downloads/ {\n"
        "            autoindex on;\n"
        "            root /srv/www;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.public_autoindex_rate_limit_policy_weak"
        for finding in result.findings
    )
