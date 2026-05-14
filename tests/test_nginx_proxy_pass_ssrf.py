from __future__ import annotations

from tests.nginx_helpers import Path, _line_number, analyze_nginx_config


def test_analyze_nginx_config_reports_proxy_pass_user_controlled_destination(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = (
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name app.example.test;\n"
        "        location / {\n"
        "            proxy_pass http://$arg_target;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "nginx.proxy_pass_user_controlled_destination"
    ]
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.line == _line_number(
        config_text,
        "proxy_pass http://$arg_target;",
    )


def test_analyze_nginx_config_reports_proxy_pass_user_controlled_destination_through_set(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name app.example.test;\n"
        "        set $backend $arg_target;\n"
        "        location / {\n"
        "            proxy_pass http://$backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert any(
        finding.rule_id == "nginx.proxy_pass_user_controlled_destination"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_proxy_pass_user_controlled_destination_through_map(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    map $arg_role $backend {\n"
        "        default upstream_a;\n"
        "        admin upstream_b;\n"
        "    }\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name app.example.test;\n"
        "        location / {\n"
        "            proxy_pass http://$backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert any(
        finding.rule_id == "nginx.proxy_pass_user_controlled_destination"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_proxy_pass_user_controlled_destination_for_path_only_interpolation(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name app.example.test;\n"
        "        location / {\n"
        "            proxy_pass http://backend/$arg_target;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.proxy_pass_user_controlled_destination"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_proxy_pass_uri_in_host_position(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name app.example.test;\n"
        "        location / {\n"
        "            proxy_pass http://backend$uri;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert any(
        finding.rule_id == "nginx.proxy_pass_user_controlled_destination"
        for finding in result.findings
    )
