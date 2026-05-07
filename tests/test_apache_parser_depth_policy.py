from tests.apache_helpers import Path, _safe_apache_config, analyze_apache_config


def test_analyze_apache_config_reports_missing_sitewide_method_policy_for_proxy_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:443>",
            "    ServerName app.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    SSLProxyEngine On",
            "    ProxyPass / https://backend.internal/",
            "</VirtualHost>",
        ),
    )

    assert "apache.sitewide_http_method_policy_missing" in _rule_ids(findings)


def test_analyze_apache_config_accepts_sitewide_method_policy_for_proxy_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:443>",
            "    ServerName app.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    SSLProxyEngine On",
            "    ProxyPass / https://backend.internal/",
            '    <Location "/">',
            "        <LimitExcept GET HEAD POST OPTIONS>",
            "            Require all denied",
            "        </LimitExcept>",
            "    </Location>",
            "</VirtualHost>",
        ),
    )

    assert "apache.sitewide_http_method_policy_missing" not in _rule_ids(findings)


def test_analyze_apache_config_reports_https_upstream_without_proxy_verify_require(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:443>",
            "    ServerName app.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    SSLProxyEngine On",
            "    ProxyPass / https://backend.internal/",
            '    <Location "/">',
            "        <LimitExcept GET HEAD POST OPTIONS>",
            "            Require all denied",
            "        </LimitExcept>",
            "    </Location>",
            "</VirtualHost>",
        ),
    )

    assert "apache.ssl_proxy_verify_not_required" in _rule_ids(findings)


def test_analyze_apache_config_accepts_https_upstream_with_proxy_verify_require(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:443>",
            "    ServerName app.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    SSLProxyEngine On",
            "    SSLProxyVerify require",
            "    ProxyPass / https://backend.internal/",
            '    <Location "/">',
            "        <LimitExcept GET HEAD POST OPTIONS>",
            "            Require all denied",
            "        </LimitExcept>",
            "    </Location>",
            "</VirtualHost>",
        ),
    )

    assert "apache.ssl_proxy_verify_not_required" not in _rule_ids(findings)


def test_analyze_apache_config_reports_https_upstream_peer_name_check_disabled(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:443>",
            "    ServerName app.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    SSLProxyEngine On",
            "    SSLProxyVerify require",
            "    SSLProxyCheckPeerName off",
            "    ProxyPass / https://backend.internal/",
            '    <Location "/">',
            "        <LimitExcept GET HEAD POST OPTIONS>",
            "            Require all denied",
            "        </LimitExcept>",
            "    </Location>",
            "</VirtualHost>",
        ),
    )

    assert "apache.ssl_proxy_peer_name_check_disabled" in _rule_ids(findings)


def _analyze_config(tmp_path: Path, config: str):
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(config, encoding="utf-8")
    result = analyze_apache_config(str(config_path))
    assert result.issues == []
    return result.findings


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}
