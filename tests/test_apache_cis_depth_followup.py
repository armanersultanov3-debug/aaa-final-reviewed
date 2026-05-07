from tests.apache_helpers import (
    Path,
    _posix_path,
    _safe_apache_config,
    _safe_apache_config_without_headers,
    analyze_apache_config,
)


def test_default_content_probe_flags_default_html(tmp_path: Path) -> None:
    web_root = tmp_path / "www"
    web_root.mkdir()
    (web_root / "index.html").write_text(
        "<html><body>Apache2 Default Page: It works!</body></html>\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            f'DocumentRoot "{_posix_path(web_root)}"',
            f'<Directory "{_posix_path(web_root)}">',
            "    AllowOverride None",
            "    Options None",
            "    Require all granted",
            "</Directory>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "apache.default_content_probe"
        for finding in result.findings
    )


def test_request_read_timeout_semantics_flags_missing_policy_when_module_loaded(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            "LoadModule reqtimeout_module modules/mod_reqtimeout.so",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "apache.request_read_timeout_semantics"
        for finding in result.findings
    )


def test_timeout_keepalive_default_policy_flags_missing_timeout_policy(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config().replace("Timeout 10\n", "", 1),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "apache.timeout_keepalive_default_policy"
        for finding in result.findings
    )


def test_permissions_policy_runtime_quality_flags_onsuccess_only_header(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config_without_headers(omit_headers={"permissions-policy"})
        + '\nHeader set Permissions-Policy "geolocation=()"',
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "apache.permissions_policy_runtime_quality"
        for finding in result.findings
    )


def test_sensitive_path_environment_policy_flags_private_directory(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Directory "/var/www/private">',
            "    Require all granted",
            "</Directory>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "apache.sensitive_path_environment_policy"
        for finding in result.findings
    )
