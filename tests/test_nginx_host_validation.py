from __future__ import annotations

from tests.nginx_helpers import Path, analyze_nginx_config


def test_analyze_nginx_config_reports_server_block_accepts_unknown_host_without_server_name(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        location / {\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert any(
        finding.rule_id == "nginx.server_block_accepts_unknown_host"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_server_block_accepts_unknown_host_for_wildcard_name(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name *.example.test;\n"
        "        root /srv/www;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert any(
        finding.rule_id == "nginx.server_block_accepts_unknown_host"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_server_block_accepts_unknown_host_for_default_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80 default_server;\n"
        "        server_name _;\n"
        "        location / {\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.server_block_accepts_unknown_host"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_server_block_accepts_unknown_host_when_host_is_rejected(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name _;\n"
        "        if ($host !~ ^example\\.test$) {\n"
        "            return 444;\n"
        "        }\n"
        "        location / {\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.server_block_accepts_unknown_host"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_server_block_accepts_unknown_host_when_host_is_rejected_with_421(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name _;\n"
        "        if ($host !~ ^example\\.test$) {\n"
        "            return 421;\n"
        "        }\n"
        "        location / {\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.server_block_accepts_unknown_host"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_server_block_accepts_unknown_host_without_content_handler(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name _;\n"
        "        add_header X-Test safe;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.server_block_accepts_unknown_host"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_server_block_accepts_unknown_host_in_stream_context(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "stream {\n"
        "    upstream backend {\n"
        "        server 127.0.0.1:9001;\n"
        "    }\n"
        "    server {\n"
        "        listen 9000;\n"
        "        proxy_pass backend;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.server_block_accepts_unknown_host"
        for finding in result.findings
    )
