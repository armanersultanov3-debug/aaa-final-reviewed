from __future__ import annotations

from tests.apache_helpers import Path, analyze_apache_config
from tests.iis_helpers import analyze_iis_config
from tests.lighttpd_helpers import analyze_lighttpd_config
from tests.lighttpd_helpers import parse_lighttpd_config
from tests.nginx_helpers import analyze_nginx_config
from webconf_audit.local.lighttpd.rules.basic_auth_over_http import (
    find_basic_auth_over_http,
)


def _rule_ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_lighttpd_reports_missing_dangerous_method_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'url.access-deny = ( ".inc", ".bak" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.missing_http_method_restrictions" in _rule_ids(result)


def test_lighttpd_accepts_explicit_dangerous_method_deny_policy(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'url.access-deny = ( ".inc", ".bak" )\n'
        '$HTTP["request-method"] =~ "^(TRACE|PUT|DELETE|CONNECT|PATCH|PROPFIND)$" {\n'
        '    url.access-deny = ( "" )\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.missing_http_method_restrictions" not in _rule_ids(result)


def test_nginx_reports_basic_auth_on_plain_http(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name admin.example.test;\n"
        '    auth_basic "private";\n'
        "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
        "    location / {\n"
        "        proxy_pass http://app;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert "nginx.auth_basic_over_http" in _rule_ids(result)


def test_nginx_does_not_report_basic_auth_on_tls(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name admin.example.test;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        '    auth_basic "private";\n'
        "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert "nginx.auth_basic_over_http" not in _rule_ids(result)


def test_nginx_does_not_report_basic_auth_on_redirect_only_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name admin.example.test;\n"
        '    auth_basic "private";\n'
        "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
        "    return 301 https://$host$request_uri;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert "nginx.auth_basic_over_http" not in _rule_ids(result)


def test_apache_reports_basic_auth_on_plain_http(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "Listen 80\n"
        "ServerSignature Off\n"
        "TraceEnable Off\n"
        "<Directory \"/srv/private\">\n"
        "    AuthType Basic\n"
        "    AuthName private\n"
        "    Require valid-user\n"
        "</Directory>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert "apache.basic_auth_over_http" in _rule_ids(result)


def test_apache_does_not_report_basic_auth_inside_tls_vhost(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "Listen 443 https\n"
        "<VirtualHost *:443>\n"
        "    ServerName secure.example.test\n"
        "    SSLEngine on\n"
        "    SSLCertificateFile cert.pem\n"
        "    SSLCertificateKeyFile cert.key\n"
        "    <Directory \"/srv/private\">\n"
        "        AuthType Basic\n"
        "        AuthName private\n"
        "        Require valid-user\n"
        "    </Directory>\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert "apache.basic_auth_over_http" not in _rule_ids(result)


def test_lighttpd_reports_basic_auth_without_ssl(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'server.modules = ( "mod_auth" )\n'
        'auth.require = ( "/private" => ( "method" => "basic", "realm" => "private", "require" => "valid-user" ) )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.basic_auth_over_http" in _rule_ids(result)


def test_lighttpd_reports_compact_basic_auth_without_ssl(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'server.modules = ( "mod_auth" )\n'
        'auth.require = ( "/private" => ( "method"=>"basic", '
        '"realm"=>"private", "require"=>"valid-user" ) )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.basic_auth_over_http" in _rule_ids(result)


def test_lighttpd_does_not_report_basic_auth_when_ssl_enabled(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'server.modules = ( "mod_auth" )\n'
        'ssl.engine = "enable"\n'
        'ssl.pemfile = "/etc/lighttpd/cert.pem"\n'
        'auth.require = ( "/private" => ( "method" => "basic", "realm" => "private", "require" => "valid-user" ) )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.basic_auth_over_http" not in _rule_ids(result)


def test_lighttpd_inherits_ssl_for_conditional_basic_auth(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'server.modules = ( "mod_auth" )\n'
        'ssl.engine = "enable"\n'
        'ssl.pemfile = "/etc/lighttpd/cert.pem"\n'
        '$HTTP["host"] == "secure.example.test" {\n'
        '    auth.require = ( "/private" => ( "method" => "basic", '
        '"realm" => "private", "require" => "valid-user" ) )\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.basic_auth_over_http" not in _rule_ids(result)


def test_lighttpd_inherits_basic_auth_for_scope_with_ssl_disabled(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'server.modules = ( "mod_auth" )\n'
        'ssl.engine = "enable"\n'
        'ssl.pemfile = "/etc/lighttpd/cert.pem"\n'
        'auth.require = ( "/private" => ( "method" => "basic", '
        '"realm" => "private", "require" => "valid-user" ) )\n'
        '$HTTP["host"] == "plain.example.test" {\n'
        '    ssl.engine = "disable"\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.basic_auth_over_http" in _rule_ids(result)


def test_lighttpd_ast_fallback_keeps_ssl_scope_local() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "secure.example.test" {\n'
        '    ssl.engine = "enable"\n'
        '}\n'
        'auth.require = ( "/private" => ( "method" => "basic", '
        '"realm" => "private", "require" => "valid-user" ) )\n',
        file_path="lighttpd.conf",
    )

    findings = find_basic_auth_over_http(ast)

    assert any(finding.rule_id == "lighttpd.basic_auth_over_http" for finding in findings)


def test_nginx_reports_weak_hsts_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        '    add_header Strict-Transport-Security "max-age=300" always;\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert "nginx.hsts_header_unsafe" in _rule_ids(result)
    assert "nginx.missing_hsts_header" not in _rule_ids(result)


def test_nginx_reports_hsts_without_include_subdomains(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        '    add_header Strict-Transport-Security "max-age=31536000" always;\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert "nginx.hsts_header_unsafe" in _rule_ids(result)


def test_nginx_accepts_strong_hsts_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        '    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert "nginx.hsts_header_unsafe" not in _rule_ids(result)
    assert "nginx.missing_hsts_header" not in _rule_ids(result)


def test_apache_reports_hsts_without_include_subdomains(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "Listen 443 https\n"
        "<VirtualHost *:443>\n"
        "    ServerName secure.example.test\n"
        "    SSLEngine on\n"
        "    SSLCertificateFile cert.pem\n"
        "    SSLCertificateKeyFile cert.key\n"
        '    Header always set Strict-Transport-Security "max-age=31536000"\n'
        "</VirtualHost>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert "apache.hsts_header_unsafe" in _rule_ids(result)
    assert "apache.missing_hsts_header" not in _rule_ids(result)


def test_apache_accepts_hsts_with_include_subdomains(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "Listen 443 https\n"
        "<VirtualHost *:443>\n"
        "    ServerName secure.example.test\n"
        "    SSLEngine on\n"
        "    SSLCertificateFile cert.pem\n"
        "    SSLCertificateKeyFile cert.key\n"
        "    Header always set Strict-Transport-Security "
        '"max-age=31536000; includeSubDomains"\n'
        "</VirtualHost>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert "apache.hsts_header_unsafe" not in _rule_ids(result)
    assert "apache.missing_hsts_header" not in _rule_ids(result)


def test_lighttpd_reports_weak_hsts_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'setenv.add-response-header = ( "Strict-Transport-Security" => "max-age=300" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.strict_transport_security_unsafe" in _rule_ids(result)
    assert "lighttpd.missing_strict_transport_security" not in _rule_ids(result)


def test_lighttpd_accepts_strong_hsts_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'setenv.add-response-header = ( "Strict-Transport-Security" => "max-age=31536000; includeSubDomains" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.strict_transport_security_unsafe" not in _rule_ids(result)
    assert "lighttpd.missing_strict_transport_security" not in _rule_ids(result)


def test_lighttpd_default_analysis_keeps_global_weak_hsts_visible(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'setenv.add-response-header = ( "Strict-Transport-Security" => "max-age=300" )\n'
        '$HTTP["host"] == "secure.example.test" {\n'
        '    setenv.add-response-header = ( "Strict-Transport-Security" => '
        '"max-age=31536000; includeSubDomains" )\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.strict_transport_security_unsafe" in _rule_ids(result)


def test_iis_reports_weak_hsts_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Strict-Transport-Security" value="max-age=300" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert "iis.hsts_header_unsafe" in _rule_ids(result)
    assert "iis.missing_hsts_header" not in _rule_ids(result)


def test_iis_accepts_strong_hsts_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert "iis.hsts_header_unsafe" not in _rule_ids(result)
    assert "iis.missing_hsts_header" not in _rule_ids(result)


def test_nginx_reports_csp_missing_frame_ancestors_without_broad_csp_unsafe(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        '    add_header Content-Security-Policy "default-src \'self\'" always;\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert "nginx.content_security_policy_missing_frame_ancestors" in _rule_ids(result)
    assert "nginx.content_security_policy_unsafe" not in _rule_ids(result)


def test_nginx_accepts_csp_with_frame_ancestors(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        '    add_header Content-Security-Policy "default-src \'self\'; frame-ancestors \'self\'" always;\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert "nginx.content_security_policy_missing_frame_ancestors" not in _rule_ids(result)


def test_apache_reports_csp_missing_frame_ancestors(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "Listen 80\n"
        "ServerSignature Off\n"
        "TraceEnable Off\n"
        "<VirtualHost *:80>\n"
        "    ServerName app.example.test\n"
        '    Header always set Content-Security-Policy "default-src \'self\'"\n'
        "</VirtualHost>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert "apache.content_security_policy_missing_frame_ancestors" in _rule_ids(result)


def test_apache_accepts_csp_with_frame_ancestors(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "Listen 80\n"
        "ServerSignature Off\n"
        "TraceEnable Off\n"
        "<VirtualHost *:80>\n"
        "    ServerName app.example.test\n"
        '    Header always set Content-Security-Policy "default-src \'self\'; frame-ancestors \'self\'"\n'
        "</VirtualHost>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert "apache.content_security_policy_missing_frame_ancestors" not in _rule_ids(result)


def test_apache_accepts_onsuccess_csp_with_frame_ancestors(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "Listen 80\n"
        "ServerSignature Off\n"
        "TraceEnable Off\n"
        "<VirtualHost *:80>\n"
        "    ServerName app.example.test\n"
        '    Header set Content-Security-Policy "default-src \'self\'; frame-ancestors \'self\'"\n'
        "</VirtualHost>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert "apache.content_security_policy_missing_frame_ancestors" not in _rule_ids(result)


def test_lighttpd_reports_csp_missing_frame_ancestors_without_broad_csp_unsafe(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'setenv.add-response-header = ( "Content-Security-Policy" => "default-src \'self\'" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.content_security_policy_missing_frame_ancestors" in _rule_ids(result)
    assert "lighttpd.content_security_policy_unsafe" not in _rule_ids(result)


def test_lighttpd_accepts_csp_with_frame_ancestors(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'setenv.add-response-header = ( "Content-Security-Policy" => "default-src \'self\'; frame-ancestors \'self\'" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.content_security_policy_missing_frame_ancestors" not in _rule_ids(result)


def test_iis_reports_csp_missing_frame_ancestors(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Content-Security-Policy" value="default-src 'self'" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert "iis.content_security_policy_missing_frame_ancestors" in _rule_ids(result)


def test_iis_accepts_csp_with_frame_ancestors(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Content-Security-Policy" value="default-src 'self'; frame-ancestors 'self'" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert "iis.content_security_policy_missing_frame_ancestors" not in _rule_ids(result)


def test_apache_reports_dedicated_legacy_tls_versions_rule(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "Listen 443 https\n"
        "<VirtualHost *:443>\n"
        "    ServerName legacy.example.test\n"
        "    SSLEngine On\n"
        "    SSLCertificateFile cert.pem\n"
        "    SSLCertificateKeyFile cert.key\n"
        "    SSLProtocol all\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert "apache.tls_legacy_versions_explicitly_enabled" in _rule_ids(result)


def test_apache_accepts_modern_tls_versions_without_dedicated_legacy_rule(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "Listen 443 https\n"
        "<VirtualHost *:443>\n"
        "    ServerName modern.example.test\n"
        "    SSLEngine On\n"
        "    SSLCertificateFile cert.pem\n"
        "    SSLCertificateKeyFile cert.key\n"
        "    SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert "apache.tls_legacy_versions_explicitly_enabled" not in _rule_ids(result)


def test_lighttpd_reports_dedicated_legacy_tls_versions_rule(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'ssl.engine = "enable"\n'
        'ssl.pemfile = "/etc/lighttpd/cert.pem"\n'
        'ssl.honor-cipher-order = "enable"\n'
        'ssl.openssl.ssl-conf-cmd = ( "MinProtocol" => "TLSv1.1" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.tls_legacy_versions_explicitly_enabled" in _rule_ids(result)


def test_lighttpd_accepts_modern_tls_versions_without_dedicated_legacy_rule(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        'ssl.engine = "enable"\n'
        'ssl.pemfile = "/etc/lighttpd/cert.pem"\n'
        'ssl.honor-cipher-order = "enable"\n'
        'ssl.openssl.ssl-conf-cmd = ( "MinProtocol" => "TLSv1.2" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert "lighttpd.tls_legacy_versions_explicitly_enabled" not in _rule_ids(result)
