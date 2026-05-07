from tests.apache_helpers import Path, _safe_apache_config, analyze_apache_config
from webconf_audit.local.apache.effective import ApacheVirtualHostContext
from webconf_audit.local.apache.parser import ApacheBlockNode
from webconf_audit.local.apache.rules._vhost_rejection_utils import listen_keys


def test_analyze_apache_config_accepts_explicit_listen_address(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_apache_config())

    assert "apache.listen_requires_explicit_address" not in _rule_ids(findings)


def test_analyze_apache_config_reports_port_only_listen(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_apache_config("Listen 80"))

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.listen_requires_explicit_address"
    ]
    assert len(matching) == 1
    assert "only a port" in matching[0].description


def test_analyze_apache_config_reports_zero_listen_address(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_apache_config("Listen 0.0.0.0:80"))

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.listen_requires_explicit_address"
    ]
    assert len(matching) == 1
    assert "all-zero" in matching[0].description


def test_analyze_apache_config_reports_hostname_listen_address(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_apache_config("Listen localhost:80"))

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.listen_requires_explicit_address"
    ]
    assert len(matching) == 1
    assert "literal IP" in matching[0].description


def test_analyze_apache_config_reports_ipv4_mapped_zero_listen_address(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config("Listen [::ffff:0.0.0.0]:80"),
    )

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.listen_requires_explicit_address"
    ]
    assert len(matching) == 1
    assert "IPv4-mapped" in matching[0].description


def test_analyze_apache_config_reports_named_server_without_ip_rewrite_policy(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config("ServerName www.example.test"),
    )

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.ip_based_requests_allowed"
    ]
    assert len(matching) == 1
    assert "www.example.test" in matching[0].description


def test_analyze_apache_config_accepts_ip_rewrite_policy(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "ServerName www.example.test",
            "RewriteEngine On",
            r"RewriteCond %{HTTP_HOST} !^www\.example\.test$ [NC]",
            r"RewriteCond %{REQUEST_URI} !^/error [NC]",
            "RewriteRule ^.(.*) - [L,F]",
        ),
    )

    assert "apache.ip_based_requests_allowed" not in _rule_ids(findings)


def test_analyze_apache_config_reports_unrelated_rewrite_directives(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "ServerName www.example.test",
            "RewriteEngine On",
            r"RewriteCond %{HTTP_HOST} !^www\.example\.test$ [NC]",
            r"RewriteCond %{REQUEST_URI} ^/health [NC]",
            "RewriteRule ^/maintenance - [F,L]",
        ),
    )

    assert "apache.ip_based_requests_allowed" in _rule_ids(findings)


def test_analyze_apache_config_reports_default_tls_vhost_without_reject(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "Listen 127.0.0.1:443 https",
            "<VirtualHost *:443>",
            "    ServerName www.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "</VirtualHost>",
        ),
    )

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.default_tls_vhost_not_rejecting_unknown_hosts"
    ]
    assert len(matching) == 1
    assert "www.example.test" in matching[0].description


def test_analyze_apache_config_accepts_rejecting_default_tls_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "Listen 127.0.0.1:443 https",
            "<VirtualHost *:443>",
            "    ServerName _",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            '    <Location "/">',
            "        Require all denied",
            "    </Location>",
            "</VirtualHost>",
        ),
    )

    assert (
        "apache.default_tls_vhost_not_rejecting_unknown_hosts"
        not in _rule_ids(findings)
    )


def test_analyze_apache_config_accepts_rewrite_rejecting_default_tls_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "Listen 127.0.0.1:443 https",
            "<VirtualHost *:443>",
            "    ServerName _",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    RewriteEngine On",
            "    RewriteRule ^ - [F,L]",
            "</VirtualHost>",
        ),
    )

    assert (
        "apache.default_tls_vhost_not_rejecting_unknown_hosts"
        not in _rule_ids(findings)
    )


def test_analyze_apache_config_accepts_nested_rewrite_rejecting_default_tls_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "Listen 127.0.0.1:443 https",
            "<VirtualHost *:443>",
            "    ServerName _",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    RewriteEngine On",
            "    <IfModule mod_rewrite.c>",
            "        RewriteRule ^ - [F,L]",
            "    </IfModule>",
            "</VirtualHost>",
        ),
    )

    assert (
        "apache.default_tls_vhost_not_rejecting_unknown_hosts"
        not in _rule_ids(findings)
    )


def test_analyze_apache_config_ignores_negated_ifmodule_rewrite_when_module_is_loaded(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "LoadModule rewrite_module modules/mod_rewrite.so",
            "Listen 127.0.0.1:443 https",
            "<VirtualHost *:443>",
            "    ServerName _",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    RewriteEngine On",
            "    <IfModule !mod_rewrite.c>",
            "        RewriteRule ^ - [F,L]",
            "    </IfModule>",
            "</VirtualHost>",
        ),
    )

    assert "apache.default_tls_vhost_not_rejecting_unknown_hosts" in _rule_ids(findings)


def test_analyze_apache_config_accepts_ifmodule_rewriteengine_for_following_rule(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "Listen 127.0.0.1:443 https",
            "<VirtualHost *:443>",
            "    ServerName _",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    <IfModule mod_rewrite.c>",
            "        RewriteEngine On",
            "    </IfModule>",
            "    RewriteRule ^ - [F,L]",
            "</VirtualHost>",
        ),
    )

    assert (
        "apache.default_tls_vhost_not_rejecting_unknown_hosts"
        not in _rule_ids(findings)
    )


def test_analyze_apache_config_reports_conditional_default_tls_vhost_reject(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "Listen 127.0.0.1:443 https",
            "<VirtualHost *:443>",
            "    ServerName _",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            '    <If "%{HTTP_HOST} == \'blocked.example\'">',
            '        <Location "/">',
            "            Require all denied",
            "        </Location>",
            "    </If>",
            "</VirtualHost>",
        ),
    )

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.default_tls_vhost_not_rejecting_unknown_hosts"
    ]
    assert len(matching) == 1


def test_analyze_apache_config_skips_non_default_tls_vhosts(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "Listen 127.0.0.1:443 https",
            "<VirtualHost *:443>",
            "    ServerName _",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    RewriteEngine On",
            "    RewriteRule ^ - [F,L]",
            "</VirtualHost>",
            "<VirtualHost *:443>",
            "    ServerName www.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "</VirtualHost>",
        ),
    )

    assert (
        "apache.default_tls_vhost_not_rejecting_unknown_hosts"
        not in _rule_ids(findings)
    )


def test_analyze_apache_config_reports_default_non_tls_vhost_without_reject(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            "</VirtualHost>",
            "<VirtualHost *:80>",
            "    ServerName api.example.test",
            "</VirtualHost>",
        ),
    )

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.default_vhost_not_rejecting_unknown_hosts"
    ]
    assert len(matching) == 1
    assert "app.example.test" in matching[0].description
    assert "shared non-TLS listen address" in matching[0].description


def test_analyze_apache_config_reports_single_named_default_non_tls_vhost_without_reject(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            "</VirtualHost>",
        ),
    )

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.default_vhost_not_rejecting_unknown_hosts"
    ]
    assert len(matching) == 1
    assert "app.example.test" in matching[0].description
    assert "shared non-TLS listen address" not in matching[0].description


def test_analyze_apache_config_accepts_rejecting_default_non_tls_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:80>",
            "    ServerName _",
            '    <Location "/">',
            "        Require all denied",
            "    </Location>",
            "</VirtualHost>",
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            "</VirtualHost>",
        ),
    )

    assert (
        "apache.default_vhost_not_rejecting_unknown_hosts"
        not in _rule_ids(findings)
    )


def test_analyze_apache_config_accepts_requireall_rejecting_default_non_tls_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:80>",
            "    ServerName _",
            '    <Location "/">',
            "        <RequireAll>",
            "            Require all denied",
            "        </RequireAll>",
            "    </Location>",
            "</VirtualHost>",
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            "</VirtualHost>",
        ),
    )

    assert (
        "apache.default_vhost_not_rejecting_unknown_hosts"
        not in _rule_ids(findings)
    )


def test_analyze_apache_config_accepts_locationmatch_catchall_default_non_tls_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            '    <LocationMatch "^/.*$">',
            "        Require all denied",
            "    </LocationMatch>",
            "</VirtualHost>",
        ),
    )

    assert (
        "apache.default_vhost_not_rejecting_unknown_hosts"
        not in _rule_ids(findings)
    )


def test_analyze_apache_config_accepts_rewrite_catchall_default_non_tls_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            "    RewriteEngine On",
            "    RewriteRule ^/.*$ - [F,L]",
            "</VirtualHost>",
        ),
    )

    assert (
        "apache.default_vhost_not_rejecting_unknown_hosts"
        not in _rule_ids(findings)
    )


def test_analyze_apache_config_accepts_redirect_only_default_non_tls_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            "    Redirect permanent / https://app.example.test/",
            "</VirtualHost>",
            "<VirtualHost *:80>",
            "    ServerName api.example.test",
            "</VirtualHost>",
        ),
    )

    assert (
        "apache.default_vhost_not_rejecting_unknown_hosts"
        not in _rule_ids(findings)
    )


def test_apache_vhost_listen_keys_are_deduplicated() -> None:
    context = ApacheVirtualHostContext(
        server_name="app.example.test",
        server_aliases=[],
        listen_address="*:80",
        listen_addresses=("*:80", "_default_:80", "*:80"),
        node=ApacheBlockNode(name="VirtualHost", args=["*:80"], children=[]),
    )

    assert listen_keys(context) == ["*:80"]


def _analyze_config(tmp_path: Path, config: str):
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(config, encoding="utf-8")
    result = analyze_apache_config(str(config_path))
    assert result.issues == []
    return result.findings


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}
