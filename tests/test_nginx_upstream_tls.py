from __future__ import annotations

from pathlib import Path

from webconf_audit.models import AnalysisResult, Finding
from tests.nginx_helpers import _line_number, analyze_nginx_config


def test_proxy_ssl_verify_off_in_http_scope_inherits_to_server_scopes(
    tmp_path: Path,
) -> None:
    config = (
        "http {\n"
        "    proxy_ssl_verify off;\n"
        "    server {\n"
        "        proxy_pass https://backend-a.internal;\n"
        "    }\n"
        "    server {\n"
        "        proxy_pass https://backend-b.internal;\n"
        "    }\n"
        "}\n"
    )
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    verify_findings = _findings_for_rule(result, "nginx.proxy_ssl_verify_disabled")
    assert {finding.location.line for finding in verify_findings} == {
        _line_number(config, "    server {", occurrence=1),
        _line_number(config, "    server {", occurrence=2),
    }


def test_proxy_ssl_verify_off_in_http_scope_inherits_to_location_scopes(
    tmp_path: Path,
) -> None:
    config = (
        "http {\n"
        "    proxy_ssl_verify off;\n"
        "    server {\n"
        "        location /api/ {\n"
        "            proxy_pass https://backend.internal;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    verify_findings = _findings_for_rule(result, "nginx.proxy_ssl_verify_disabled")
    assert [finding.location.line for finding in verify_findings] == [
        _line_number(config, "        location /api/ {"),
    ]


def test_proxy_ssl_verify_server_override_only_reports_overridden_scope(
    tmp_path: Path,
) -> None:
    config = (
        "http {\n"
        "    proxy_ssl_verify on;\n"
        "    server {\n"
        "        proxy_ssl_verify off;\n"
        "        proxy_pass https://backend-a.internal;\n"
        "    }\n"
        "    server {\n"
        "        proxy_pass https://backend-b.internal;\n"
        "    }\n"
        "}\n"
    )
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    verify_findings = _findings_for_rule(result, "nginx.proxy_ssl_verify_disabled")
    assert [finding.location.line for finding in verify_findings] == [
        _line_number(config, "    server {", occurrence=1),
    ]


def test_proxy_ssl_verify_disabled_when_not_explicitly_enabled(tmp_path: Path) -> None:
    config = (
        "server {\n"
        "    proxy_pass https://backend.internal;\n"
        "}\n"
    )
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    verify_findings = _findings_for_rule(result, "nginx.proxy_ssl_verify_disabled")
    assert [finding.location.line for finding in verify_findings] == [
        _line_number(config, "server {"),
    ]


def test_proxy_pass_over_http_does_not_trigger_upstream_tls_rules(tmp_path: Path) -> None:
    config = (
        "server {\n"
        "    proxy_ssl_verify off;\n"
        "    proxy_pass http://backend.internal;\n"
        "}\n"
    )
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert not _findings_for_rule(result, "nginx.proxy_ssl_verify_disabled")
    assert not _findings_for_rule(
        result,
        "nginx.proxy_ssl_trusted_certificate_missing",
    )


def test_proxy_ssl_verify_on_with_trusted_certificate_is_accepted(
    tmp_path: Path,
) -> None:
    config = (
        "http {\n"
        "    proxy_ssl_verify on;\n"
        "    proxy_ssl_trusted_certificate /etc/nginx/upstream-ca.pem;\n"
        "    server {\n"
        "        proxy_pass https://backend.internal;\n"
        "    }\n"
        "}\n"
    )
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert not _findings_for_rule(result, "nginx.proxy_ssl_verify_disabled")
    assert not _findings_for_rule(
        result,
        "nginx.proxy_ssl_trusted_certificate_missing",
    )


def test_proxy_ssl_verify_on_without_trusted_certificate_reports_missing_bundle(
    tmp_path: Path,
) -> None:
    config = (
        "server {\n"
        "    proxy_ssl_verify on;\n"
        "    proxy_pass https://backend.internal;\n"
        "}\n"
    )
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    trusted_certificate_findings = _findings_for_rule(
        result,
        "nginx.proxy_ssl_trusted_certificate_missing",
    )
    assert [finding.location.line for finding in trusted_certificate_findings] == [
        _line_number(config, "server {"),
    ]
    assert not _findings_for_rule(result, "nginx.proxy_ssl_verify_disabled")


def _findings_for_rule(result: AnalysisResult, rule_id: str) -> list[Finding]:
    return [finding for finding in result.findings if finding.rule_id == rule_id]
