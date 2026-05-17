from __future__ import annotations

from tests.nginx_helpers import Path, _line_number, analyze_nginx_config


def test_analyze_nginx_config_reports_proxy_set_header_host_http_host(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = (
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name app.example.test;\n"
        "        location / {\n"
        "            proxy_set_header Host $http_host;\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "nginx.proxy_set_header_host_spoofing"
    ]
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.line == _line_number(
        config_text,
        "proxy_set_header Host $http_host;",
    )


def test_analyze_nginx_config_reports_proxy_set_header_host_named_capture(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = (
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name app.example.test;\n"
        "        location ~ ^/tenant/(?<tenant_host>[^/]+)$ {\n"
        "            proxy_set_header Host $tenant_host;\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert any(
        finding.rule_id == "nginx.proxy_set_header_host_spoofing"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_proxy_set_header_host_host_variable(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name app.example.test;\n"
        "        location / {\n"
        "            proxy_set_header Host $host;\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.proxy_set_header_host_spoofing"
        for finding in result.findings
    )
