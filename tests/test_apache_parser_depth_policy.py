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


def test_analyze_apache_config_reports_main_server_sitewide_method_policy_with_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "SSLProxyEngine On",
            "ProxyPass / https://main-backend.internal/",
            "<VirtualHost *:443>",
            "    ServerName app.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "</VirtualHost>",
        ),
    )

    assert "apache.sitewide_http_method_policy_missing" in _rule_ids(findings)


def test_analyze_apache_config_ignores_disabled_location_for_sitewide_policy(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "LoadModule proxy_module modules/mod_proxy.so",
            "<IfModule !mod_proxy.c>",
            '    <Location "/api">',
            "        Require all granted",
            "    </Location>",
            "</IfModule>",
        ),
    )

    assert "apache.sitewide_http_method_policy_missing" not in _rule_ids(findings)


def test_analyze_apache_config_skips_unknown_negated_ifmodule_location_for_sitewide_policy(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<IfModule !mod_proxy.c>",
            '    <Location "/uploads">',
            "        Require all granted",
            "    </Location>",
            "</IfModule>",
        ),
    )

    assert "apache.sitewide_http_method_policy_missing" not in _rule_ids(findings)


def test_analyze_apache_config_reports_vhost_permissive_location_overriding_global_policy(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            '<Location "/">',
            "    <LimitExcept GET HEAD POST OPTIONS>",
            "        Require all denied",
            "    </LimitExcept>",
            "</Location>",
            "<VirtualHost *:443>",
            "    ServerName app.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    SSLProxyEngine On",
            "    ProxyPass / https://backend.internal/",
            '    <Location "/">',
            "        Require all granted",
            "    </Location>",
            "</VirtualHost>",
        ),
    )

    assert "apache.sitewide_http_method_policy_missing" in _rule_ids(findings)


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


def test_analyze_apache_config_handles_https_upstream_proxy_with_options(
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
            "    ProxyPass / https://backend.internal/ retry=1",
            '    <Location "/">',
            "        <LimitExcept GET HEAD POST OPTIONS>",
            "            Require all denied",
            "        </LimitExcept>",
            "    </Location>",
            "</VirtualHost>",
        ),
    )

    assert "apache.ssl_proxy_verify_not_required" in _rule_ids(findings)

    accepted_findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:443>",
            "    ServerName app.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    SSLProxyEngine On",
            "    SSLProxyVerify require",
            "    ProxyPass / https://backend.internal/ retry=1",
            '    <Location "/">',
            "        <LimitExcept GET HEAD POST OPTIONS>",
            "            Require all denied",
            "        </LimitExcept>",
            "    </Location>",
            "</VirtualHost>",
        ),
    )

    assert "apache.ssl_proxy_verify_not_required" not in _rule_ids(accepted_findings)


def test_analyze_apache_config_reports_main_server_https_upstream_without_proxy_verify(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "SSLProxyEngine On",
            "ProxyPass / https://main-backend.internal/",
            "<VirtualHost *:443>",
            "    ServerName app.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "</VirtualHost>",
        ),
    )

    assert "apache.ssl_proxy_verify_not_required" in _rule_ids(findings)


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


def test_analyze_apache_config_accepts_https_upstream_with_peer_name_check_enabled(
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

    assert "apache.ssl_proxy_peer_name_check_disabled" not in _rule_ids(findings)


def test_analyze_apache_config_reports_main_server_proxy_peer_name_check_disabled(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config(
        "SSLProxyEngine On",
        "SSLProxyVerify require",
        "SSLProxyCheckPeerName off",
        "ProxyPass / https://main-backend.internal/",
        "<VirtualHost *:443>",
        "    ServerName app.example.test",
        "    SSLEngine On",
        "    SSLCertificateFile conf/server.crt",
        "    SSLCertificateKeyFile conf/server.key",
        "</VirtualHost>",
    )
    findings = _analyze_config(tmp_path, config)

    assert "apache.ssl_proxy_peer_name_check_disabled" in _rule_ids(findings)
    finding = _first_finding(findings, "apache.ssl_proxy_peer_name_check_disabled")
    assert finding.location.line == _line_number(config, "SSLProxyCheckPeerName off")


def test_analyze_apache_config_accepts_unsatisfiable_requireall_method_policy(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            '<Location "/api">',
            "    <RequireAll>",
            "        Require method GET",
            "        Require method TRACE",
            "    </RequireAll>",
            "</Location>",
        ),
    )

    assert "apache.http_method_policy_allows_unapproved" not in _rule_ids(findings)


def test_analyze_apache_config_accepts_requireall_deny_all_with_unapproved_method(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            '<Location "/api">',
            "    <RequireAll>",
            "        Require all denied",
            "        Require method TRACE",
            "    </RequireAll>",
            "</Location>",
        ),
    )

    assert "apache.http_method_policy_allows_unapproved" not in _rule_ids(findings)


def _analyze_config(tmp_path: Path, config: str):
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(config, encoding="utf-8")
    result = analyze_apache_config(str(config_path))
    assert result.issues == []
    return result.findings


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def _first_finding(findings, rule_id: str):
    return next(finding for finding in findings if finding.rule_id == rule_id)


def _line_number(config: str, needle: str) -> int:
    return next(
        line_number
        for line_number, line in enumerate(config.splitlines(), start=1)
        if needle in line
    )
