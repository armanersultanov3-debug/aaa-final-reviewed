from tests.apache_helpers import Path, _safe_apache_config, analyze_apache_config

_NEW_TLS_RULE_IDS = {
    "apache.ssl_cipher_suite_missing",
    "apache.ssl_compression_enabled",
    "apache.ssl_honor_cipher_order_not_on",
    "apache.ssl_insecure_renegotiation_enabled",
    "apache.ssl_protocol_missing_or_weak",
    "apache.ssl_session_cache_missing",
    "apache.ssl_stapling_cache_missing",
    "apache.ssl_use_stapling_not_on",
}

_SAFE_TLS_LINES = {
    "listen": "Listen 443 https",
    "session_cache": "SSLSessionCache shmcb:logs/ssl_scache(512000)",
    "stapling_cache": "SSLStaplingCache shmcb:logs/ssl_stapling(32768)",
    "vhost_open": "<VirtualHost *:443>",
    "server_name": "    ServerName secure.test",
    "engine": "    SSLEngine On",
    "certificate": "    SSLCertificateFile conf/server.crt",
    "certificate_key": "    SSLCertificateKeyFile conf/server.key",
    "protocol": "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
    "cipher_suite": "    SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES",
    "honor_cipher_order": "    SSLHonorCipherOrder On",
    "compression": "    SSLCompression Off",
    "renegotiation": "    SSLInsecureRenegotiation Off",
    "stapling": "    SSLUseStapling On",
    "vhost_close": "</VirtualHost>",
}


def test_safe_apache_http_config_does_not_report_tls_rules(tmp_path: Path) -> None:
    findings = _analyze_config(tmp_path, _safe_apache_config())

    assert _rule_ids(findings).isdisjoint(_NEW_TLS_RULE_IDS)


def test_safe_apache_tls_config_does_not_report_tls_rules(tmp_path: Path) -> None:
    findings = _analyze_config(tmp_path, _safe_tls_config())

    assert _rule_ids(findings).isdisjoint(_NEW_TLS_RULE_IDS)


def test_analyze_apache_config_uses_any_global_listen_for_tls_intent(
    tmp_path: Path,
) -> None:
    config = "\n".join(
        [
            "ServerSignature Off",
            "TraceEnable Off",
            "ServerTokens Prod",
            "LimitRequestBody 102400",
            "LimitRequestFields 100",
            "ErrorLog logs/error_log",
            "CustomLog logs/access_log combined",
            "Listen 443 https",
            "Listen 80",
        ]
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.ssl_protocol_missing_or_weak" in _rule_ids(findings)


def test_analyze_apache_config_uses_https_listen_protocol_for_virtualhost(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config(
        "Listen 10443 https",
        "<VirtualHost *:10443>",
        "    ServerName secure-alt.test",
        "</VirtualHost>",
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.ssl_protocol_missing_or_weak" in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_ssl_protocol(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_tls_config(omit={"protocol"}))

    assert "apache.ssl_protocol_missing_or_weak" in _rule_ids(findings)


def test_analyze_apache_config_reports_weak_ssl_protocol(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(replacements={"protocol": "    SSLProtocol all"}),
    )

    assert "apache.ssl_protocol_missing_or_weak" in _rule_ids(findings)


def test_analyze_apache_config_accepts_protocol_subtracting_legacy_versions(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(
            replacements={
                "protocol": "    SSLProtocol -all +TLSv1.2 +TLSv1.3",
            }
        ),
    )

    assert "apache.ssl_protocol_missing_or_weak" not in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_ssl_cipher_suite(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_tls_config(omit={"cipher_suite"}))

    assert "apache.ssl_cipher_suite_missing" in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_ssl_honor_cipher_order(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_tls_config(omit={"honor_cipher_order"}))

    assert "apache.ssl_honor_cipher_order_not_on" in _rule_ids(findings)


def test_analyze_apache_config_reports_ssl_honor_cipher_order_off(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(
            replacements={"honor_cipher_order": "    SSLHonorCipherOrder Off"}
        ),
    )

    assert "apache.ssl_honor_cipher_order_not_on" in _rule_ids(findings)


def test_analyze_apache_config_reports_ssl_compression_on(tmp_path: Path) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(replacements={"compression": "    SSLCompression On"}),
    )

    assert "apache.ssl_compression_enabled" in _rule_ids(findings)


def test_analyze_apache_config_reports_insecure_renegotiation_on(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(
            replacements={"renegotiation": "    SSLInsecureRenegotiation On"}
        ),
    )

    assert "apache.ssl_insecure_renegotiation_enabled" in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_ssl_use_stapling(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_tls_config(omit={"stapling"}))

    assert "apache.ssl_use_stapling_not_on" in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_ssl_stapling_cache(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_tls_config(omit={"stapling_cache"}))

    assert "apache.ssl_stapling_cache_missing" in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_ssl_session_cache(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_tls_config(omit={"session_cache"}))

    assert "apache.ssl_session_cache_missing" in _rule_ids(findings)


def test_analyze_apache_config_reports_disabled_ssl_session_cache(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(replacements={"session_cache": "SSLSessionCache none"}),
    )

    assert "apache.ssl_session_cache_missing" in _rule_ids(findings)


def test_analyze_apache_config_reports_disabled_ssl_session_cache_nonenotnull(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(
            replacements={"session_cache": "SSLSessionCache nonenotnull"}
        ),
    )

    assert "apache.ssl_session_cache_missing" in _rule_ids(findings)


def test_analyze_apache_config_applies_global_tls_policy_to_vhost(
    tmp_path: Path,
) -> None:
    config = _safe_tls_config(
        omit={
            "protocol",
            "cipher_suite",
            "honor_cipher_order",
            "compression",
            "renegotiation",
            "stapling",
        },
        extra_lines=[
            "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
            "SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES",
            "SSLHonorCipherOrder On",
            "SSLCompression Off",
            "SSLInsecureRenegotiation Off",
            "SSLUseStapling On",
        ],
    )

    findings = _analyze_config(tmp_path, config)

    assert _rule_ids(findings).isdisjoint(_NEW_TLS_RULE_IDS)


def _safe_tls_config(
    *,
    omit: set[str] | None = None,
    replacements: dict[str, str] | None = None,
    extra_lines: list[str] | None = None,
) -> str:
    omitted = omit or set()
    overrides = replacements or {}
    lines = [
        overrides.get(key, line)
        for key, line in _SAFE_TLS_LINES.items()
        if key not in omitted
    ]
    lines.extend(extra_lines or [])
    return _safe_apache_config(*lines)


def _analyze_config(tmp_path: Path, config: str):
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(config, encoding="utf-8")
    result = analyze_apache_config(str(config_path))
    assert result.issues == []
    return result.findings


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}
