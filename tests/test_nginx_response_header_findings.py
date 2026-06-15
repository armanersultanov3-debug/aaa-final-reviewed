from __future__ import annotations

from webconf_audit.local.nginx import analyze_nginx_config


def _rule_ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_missing_csp_finding_detects_location_replacement_gap(tmp_path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    add_header Content-Security-Policy \"default-src 'self'\" always;\n"
        "    server {\n"
        "        listen 80;\n"
        "        location /app/ {\n"
        "            add_header X-Content-Type-Options nosniff;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert "nginx.missing_content_security_policy" in _rule_ids(result)


def test_csp_unsafe_uses_conjunction_across_multiple_enforcing_policies(
    tmp_path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    add_header Content-Security-Policy \"script-src 'unsafe-inline'\" always;\n"
        "    add_header Content-Security-Policy \"script-src 'self'\" always;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert "nginx.content_security_policy_unsafe" not in _rule_ids(result)
