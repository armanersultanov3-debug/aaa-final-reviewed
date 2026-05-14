from __future__ import annotations

from tests.nginx_helpers import Path, _line_number, _safe_server_block, analyze_nginx_config


def test_analyze_nginx_config_reports_crlf_in_return_with_tainted_set_chain(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = _safe_server_block(
        "listen 80;",
        "set $redirect_target $arg_next;",
        "return 302 https://example.test/$redirect_target;",
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "nginx.crlf_in_return"
    ]
    assert len(matching) == 1
    assert matching[0].location is not None
    assert matching[0].location.line == _line_number(
        config_text,
        "return 302 https://example.test/$redirect_target;",
    )


def test_analyze_nginx_config_does_not_report_crlf_in_return_for_fixed_target(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "return 302 https://example.test/login;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.crlf_in_return"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_crlf_in_add_header(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_text = _safe_server_block(
        "listen 80;",
        'add_header Set-Cookie "$arg_session; Secure" always;',
    )
    config_path.write_text(config_text, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "nginx.crlf_in_add_header"
    ]
    assert len(matching) == 1
    assert matching[0].metadata["header_name"] == "Set-Cookie"
    assert matching[0].location is not None
    assert matching[0].location.line == _line_number(
        config_text,
        'add_header Set-Cookie "$arg_session; Secure" always;',
    )


def test_analyze_nginx_config_does_not_report_crlf_in_add_header_for_fixed_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            'add_header X-Trace "static-value" always;',
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.crlf_in_add_header"
        for finding in result.findings
    )
