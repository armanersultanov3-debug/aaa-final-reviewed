from tests.apache_helpers import Path, _safe_apache_config, analyze_apache_config


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


def _analyze_config(tmp_path: Path, config: str):
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(config, encoding="utf-8")
    result = analyze_apache_config(str(config_path))
    assert result.issues == []
    return result.findings


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}
