from tests.apache_helpers import (
    Path,
    _posix_path,
    _safe_apache_config,
    _safe_apache_config_without_headers,
    analyze_apache_config,
)
from webconf_audit.local.apache.parser import parse_apache_config
import webconf_audit.local.apache.rules.default_content_probe as default_content_probe_rule


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
    base_lines = _safe_apache_config().splitlines()
    filtered_lines: list[str] = []
    removed_timeout = False
    for line in base_lines:
        if not removed_timeout and line.lstrip().startswith("Timeout"):
            removed_timeout = True
            continue
        filtered_lines.append(line)

    assert removed_timeout
    config_path.write_text(
        "\n".join(filtered_lines),
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


def test_request_read_timeout_semantics_accepts_valid_minrate_policy(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            "LoadModule reqtimeout_module modules/mod_reqtimeout.so",
            "RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.request_read_timeout_semantics"
        for finding in result.findings
    )


def test_request_read_timeout_semantics_flags_invalid_minrate_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            "LoadModule reqtimeout_module modules/mod_reqtimeout.so",
            "RequestReadTimeout header=20-40,MinRate=0 body=20,MinRate=500",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert any(
        finding.rule_id == "apache.request_read_timeout_semantics"
        for finding in result.findings
    )


def test_sensitive_path_environment_policy_ignores_substring_in_regular_word(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            '<Directory "/var/www/attempt">',
            "    Require all granted",
            "</Directory>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "apache.sensitive_path_environment_policy"
        for finding in result.findings
    )


def test_default_content_probe_reuses_seen_files_for_clean_shared_document_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    web_root = tmp_path / "www"
    web_root.mkdir()
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _safe_apache_config(
            f'DocumentRoot "{_posix_path(web_root)}"',
        ),
        encoding="utf-8",
    )
    config_ast = parse_apache_config(str(config_path))
    checked_paths: list[str] = []
    shared_context = object()

    def _fake_sample_content_finding(sample_path: Path, markers: tuple[str, ...]):
        checked_paths.append(str(sample_path))
        return None

    def _fake_extract_document_root(*args, **kwargs):
        return web_root

    monkeypatch.setattr(
        default_content_probe_rule,
        "_sample_content_finding",
        _fake_sample_content_finding,
    )
    monkeypatch.setattr(
        default_content_probe_rule,
        "extract_virtualhost_contexts",
        lambda config_ast: [shared_context],
    )
    monkeypatch.setattr(
        default_content_probe_rule,
        "extract_document_root",
        _fake_extract_document_root,
    )

    findings = default_content_probe_rule.find_default_content_probe(config_ast)

    assert findings == []
    assert len(checked_paths) == len(default_content_probe_rule._SAMPLE_PATH_MARKERS)
