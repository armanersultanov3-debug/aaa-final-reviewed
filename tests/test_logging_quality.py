from __future__ import annotations

from pathlib import Path

from tests.apache_helpers import _safe_apache_config, analyze_apache_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config


def test_nginx_log_format_reports_missing_observability_fields(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        '    log_format main "$time_iso8601 $remote_addr $remote_user '
        '$request $status $http_user_agent";\n'
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate /etc/ssl/cert.pem;\n"
        "        ssl_certificate_key /etc/ssl/key.pem;\n"
        "        access_log /var/log/nginx/access.log main;\n"
        "        location /api/ { proxy_pass http://backend; }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    finding = _only_finding(result.findings, "nginx.log_format_missing_fields")
    assert "request ID" in finding.description
    assert "forwarded chain" in finding.description
    assert "upstream timing" in finding.description
    assert "TLS protocol/cipher" in finding.description


def test_nginx_log_format_accepts_recommended_observability_fields(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        '    log_format main "$time_iso8601 $remote_addr $remote_user '
        '$request $status $http_user_agent $request_id $http_x_forwarded_for '
        '$upstream_response_time $ssl_protocol $ssl_cipher";\n'
        "    server {\n"
        "        listen 443 ssl;\n"
        "        ssl_certificate /etc/ssl/cert.pem;\n"
        "        ssl_certificate_key /etc/ssl/key.pem;\n"
        "        access_log /var/log/nginx/access.log main;\n"
        "        location /api/ { proxy_pass http://backend; }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert "nginx.log_format_missing_fields" not in _rule_ids(result.findings)


def test_nginx_log_format_does_not_inherit_usage_from_sibling_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        '    log_format static "$time_iso8601 $remote_addr $remote_user '
        '$request $status $http_user_agent";\n'
        '    log_format proxy "$time_iso8601 $remote_addr $remote_user '
        "$request $status $http_user_agent $request_id $http_x_forwarded_for "
        '$upstream_response_time";\n'
        "    server {\n"
        "        listen 80;\n"
        "        access_log /var/log/nginx/static.log static;\n"
        "    }\n"
        "    server {\n"
        "        listen 80;\n"
        "        access_log /var/log/nginx/proxy.log proxy;\n"
        "        location /api/ { proxy_pass http://backend; }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert "nginx.log_format_missing_fields" not in _rule_ids(result.findings)


def test_nginx_log_format_does_not_treat_plain_443_listener_as_tls(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        '    log_format main "$time_iso8601 $remote_addr $remote_user '
        '$request $status $http_user_agent";\n'
        "    server {\n"
        "        listen 443;\n"
        "        access_log /var/log/nginx/access.log main;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert "nginx.log_format_missing_fields" not in _rule_ids(result.findings)


def test_apache_log_format_reports_missing_observability_fields(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config(
        "SSLEngine on",
        'LogFormat "%h %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" audit',
    ).replace(
        "CustomLog logs/access_log combined",
        "CustomLog logs/access_log audit",
    )
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    finding = _only_finding(result.findings, "apache.log_format_missing_fields")
    assert "request ID" in finding.description
    assert "forwarded chain" in finding.description
    assert "request timing" in finding.description
    assert "TLS protocol/cipher" in finding.description


def test_apache_log_format_accepts_recommended_observability_fields(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config(
        'LogFormat "%a %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" '
        '\\"%{User-Agent}i\\" \\"%{X-Request-ID}i\\" \\"%{X-Forwarded-For}i\\" '
        '%D %{SSL_PROTOCOL}x %{SSL_CIPHER}x" audit',
    ).replace(
        "CustomLog logs/access_log combined",
        "CustomLog logs/access_log audit",
    )
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert "apache.log_format_missing_fields" not in _rule_ids(result.findings)


def test_apache_log_format_applies_tls_fields_only_to_tls_customlog(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            'LogFormat "%a %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" '
            '\\"%{User-Agent}i\\" \\"%{X-Request-ID}i\\" '
            '\\"%{X-Forwarded-For}i\\" %D" http_audit',
            'LogFormat "%a %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" '
            '\\"%{User-Agent}i\\" \\"%{X-Request-ID}i\\" '
            '\\"%{X-Forwarded-For}i\\" %D %{SSL_PROTOCOL}x %{SSL_CIPHER}x" '
            "tls_audit",
            "<VirtualHost *:80>",
            "    CustomLog logs/http_access_log http_audit",
            "</VirtualHost>",
            "<VirtualHost *:443>",
            "    SSLEngine on",
            "    CustomLog logs/tls_access_log tls_audit",
            "</VirtualHost>",
        ).replace(
            "CustomLog logs/access_log combined",
            "",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert "apache.log_format_missing_fields" not in _rule_ids(result.findings)


def test_lighttpd_access_log_format_reports_missing_recommended_fields(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.modules = ("mod_accesslog")\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'accesslog.filename = "/var/log/lighttpd/access.log"\n'
        'accesslog.format = "%h %t \\"%r\\" %>s"\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(config_path)

    assert result.issues == []
    finding = _only_finding(
        result.findings,
        "lighttpd.access_log_format_missing_fields",
    )
    assert "user-agent" in finding.description


def test_lighttpd_access_log_format_accepts_recommended_fields(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.modules = ("mod_accesslog")\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'accesslog.filename = "/var/log/lighttpd/access.log"\n'
        'accesslog.format = "%h %u %t \\"%r\\" %>s %b \\"%{User-Agent}i\\""\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(config_path)

    assert result.issues == []
    assert "lighttpd.access_log_format_missing_fields" not in _rule_ids(
        result.findings
    )


def test_lighttpd_access_log_format_checks_conditional_scopes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.modules = ("mod_accesslog")\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        '$HTTP["host"] == "weak.example" {\n'
        '    accesslog.filename = "/var/log/lighttpd/weak.log"\n'
        '    accesslog.format = "%h %t \\"%r\\" %>s"\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(config_path)

    assert result.issues == []
    assert "lighttpd.access_log_format_missing_fields" in _rule_ids(
        result.findings
    )


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def _only_finding(findings, rule_id: str):
    matches = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matches) == 1
    return matches[0]
