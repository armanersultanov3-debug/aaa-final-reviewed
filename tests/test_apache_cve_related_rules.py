from tests.apache_helpers import Path, _safe_apache_config, analyze_apache_config


def _analyze_config(tmp_path: Path, config_text: str):
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(config_text, encoding="utf-8")
    result = analyze_apache_config(str(config_path))
    assert result.issues == []
    return result.findings


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def _single_finding(findings, rule_id: str):
    matches = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matches) == 1
    return matches[0]


def _line_number(config_text: str, needle: str) -> int:
    for line_number, line in enumerate(config_text.splitlines(), start=1):
        if needle in line:
            return line_number
    raise AssertionError(f"Could not find {needle!r}")


def test_allow_encoded_slashes_on_with_merge_slashes_off_is_reported(tmp_path: Path):
    config = _safe_apache_config(
        "AllowEncodedSlashes On",
        "MergeSlashes Off",
    )

    finding = _single_finding(
        _analyze_config(tmp_path, config),
        "apache.allow_encoded_slashes_with_merge_slashes_off",
    )

    assert "CVE-2025-59775" in finding.description
    assert finding.location is not None
    assert finding.location.line == _line_number(config, "AllowEncodedSlashes On")


def test_allow_encoded_slashes_without_merge_slashes_off_is_not_reported(
    tmp_path: Path,
):
    config = _safe_apache_config(
        "AllowEncodedSlashes On",
        "MergeSlashes On",
    )

    assert "apache.allow_encoded_slashes_with_merge_slashes_off" not in _rule_ids(
        _analyze_config(tmp_path, config)
    )


def test_ssl_engine_optional_is_reported(tmp_path: Path):
    config = _safe_apache_config("SSLEngine optional")

    finding = _single_finding(
        _analyze_config(tmp_path, config),
        "apache.ssl_engine_optional",
    )

    assert "CVE-2025-49812" in finding.description
    assert finding.location is not None
    assert finding.location.line == _line_number(config, "SSLEngine optional")


def test_proxy_http2_backend_with_preserve_host_is_reported(tmp_path: Path):
    config = _safe_apache_config(
        "ProxyPreserveHost On",
        'ProxyPass "/app" "h2://backend.example.test/"',
    )

    finding = _single_finding(
        _analyze_config(tmp_path, config),
        "apache.proxy_http2_backend_with_preserve_host",
    )

    assert "CVE-2025-49630" in finding.description
    assert finding.location is not None
    assert finding.location.line == _line_number(config, "ProxyPass")


def test_http2_backend_without_preserve_host_on_is_not_reported(tmp_path: Path):
    config = _safe_apache_config(
        "ProxyPreserveHost Off",
        'ProxyPass "/app" "h2://backend.example.test/"',
    )

    assert "apache.proxy_http2_backend_with_preserve_host" not in _rule_ids(
        _analyze_config(tmp_path, config)
    )
