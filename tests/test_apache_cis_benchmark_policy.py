from tests.apache_helpers import (
    Path,
    analyze_apache_config,
    _safe_apache_config,
)

_NEW_CIS_RULE_IDS = {
    "apache.allowoverride_not_none",
    "apache.error_log_unsafe_destination",
    "apache.generated_artifacts_not_restricted",
    "apache.ht_files_not_restricted",
    "apache.log_format_missing_fields",
    "apache.log_level_too_restrictive",
    "apache.missing_log_format",
    "apache.sensitive_config_files_not_restricted",
    "apache.vcs_metadata_not_restricted",
}


def test_apache_cis_baseline_does_not_report_new_benchmark_rules(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_apache_config())

    assert _rule_ids(findings).isdisjoint(_NEW_CIS_RULE_IDS)


def test_analyze_apache_config_reports_missing_root_allowoverride_none(
    tmp_path: Path,
) -> None:
    config = _remove_simple_block(_safe_apache_config(), "<Directory />")

    findings = _analyze_config(tmp_path, config)

    assert "apache.allowoverride_not_none" in _rule_ids(findings)


def test_analyze_apache_config_reports_non_none_allowoverride_scope(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config(
        '<Directory "/var/www/html">',
        "    AllowOverride AuthConfig",
        "</Directory>",
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.allowoverride_not_none" in _rule_ids(findings)


def test_analyze_apache_config_uses_last_allowoverride_for_same_directory(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config(
        '<Directory "/var/www/html">',
        "    AllowOverride AuthConfig",
        "</Directory>",
        '<Directory "/var/www/html">',
        "    AllowOverride None",
        "</Directory>",
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.allowoverride_not_none" not in _rule_ids(findings)


def test_analyze_apache_config_keeps_prior_allowoverride_when_later_block_omits_it(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config(
        '<Directory "/var/www/html">',
        "    AllowOverride AuthConfig",
        "</Directory>",
        '<Directory "/var/www/html">',
        "    Options -Indexes",
        "</Directory>",
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.allowoverride_not_none" in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_ht_file_restriction(
    tmp_path: Path,
) -> None:
    config = _remove_simple_block(_safe_apache_config(), '<FilesMatch "^\\.ht">')

    findings = _analyze_config(tmp_path, config)

    assert "apache.ht_files_not_restricted" in _rule_ids(findings)


def test_analyze_apache_config_does_not_count_html_denial_as_ht_file_restriction(
    tmp_path: Path,
) -> None:
    config = _remove_simple_block(
        _safe_apache_config(
            '<FilesMatch "^\\.html$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        '<FilesMatch "^\\.ht">',
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.ht_files_not_restricted" in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_sensitive_config_extension_restriction(
    tmp_path: Path,
) -> None:
    config = _remove_simple_block(
        _safe_apache_config(),
        '<FilesMatch "\\.(conf|env|ini|log|orig|save|sql|tmp)$">',
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.sensitive_config_files_not_restricted" in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_vcs_metadata_restriction(
    tmp_path: Path,
) -> None:
    config = _remove_simple_block(
        _safe_apache_config(),
        '<DirectoryMatch "/\\.(git|svn)(/|$)">',
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.vcs_metadata_not_restricted" in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_generated_artifact_restriction(
    tmp_path: Path,
) -> None:
    config = _remove_simple_block(
        _safe_apache_config(),
        '<FilesMatch "(^|/)(Thumbs\\.db|composer\\.(json|lock)|package-lock\\.json|\\.DS_Store|\\.npmrc|\\.yarnrc)$">',
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.generated_artifacts_not_restricted" in _rule_ids(findings)


def test_analyze_apache_config_accepts_generated_artifact_restriction(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_apache_config())

    assert "apache.generated_artifacts_not_restricted" not in _rule_ids(findings)


def test_analyze_apache_config_does_not_count_gitignore_as_vcs_restriction(
    tmp_path: Path,
) -> None:
    config = _remove_simple_block(
        _safe_apache_config(
            '<DirectoryMatch "/\\.gitignore$">',
            "    Require all denied",
            "</DirectoryMatch>",
        ),
        '<DirectoryMatch "/\\.(git|svn)(/|$)">',
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.vcs_metadata_not_restricted" in _rule_ids(findings)


def test_analyze_apache_config_reports_error_log_to_dev_null(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config().replace(
        "ErrorLog logs/error_log",
        "ErrorLog /dev/null",
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.error_log_unsafe_destination" in _rule_ids(findings)


def test_analyze_apache_config_reports_restrictive_log_level(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config().replace("LogLevel notice", "LogLevel error")

    findings = _analyze_config(tmp_path, config)

    assert "apache.log_level_too_restrictive" in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_log_format_for_customlog(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config().replace(
        "CustomLog logs/access_log combined",
        "CustomLog logs/access_log audit",
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.missing_log_format" in _rule_ids(findings)


def test_analyze_apache_config_reports_custom_log_format_missing_fields(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config(
        'LogFormat "%h %u %t \\"%r\\" %>s %b" audit',
    ).replace(
        "CustomLog logs/access_log combined",
        "CustomLog logs/access_log audit",
    )

    findings = _analyze_config(tmp_path, config)

    assert "apache.log_format_missing_fields" in _rule_ids(findings)


def test_analyze_apache_config_accepts_custom_log_format_with_required_fields(
    tmp_path: Path,
) -> None:
    config = _safe_apache_config(
        'LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" '
        '\\"%{User-Agent}i\\" \\"%{X-Request-ID}i\\" \\"%{X-Forwarded-For}i\\" %D" audit',
    ).replace(
        "CustomLog logs/access_log combined",
        "CustomLog logs/access_log audit",
    )

    findings = _analyze_config(tmp_path, config)

    rule_ids = _rule_ids(findings)
    assert "apache.missing_log_format" not in rule_ids
    assert "apache.log_format_missing_fields" not in rule_ids


def _analyze_config(tmp_path: Path, config: str):
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(config, encoding="utf-8")
    result = analyze_apache_config(str(config_path))
    assert result.issues == []
    return result.findings


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def _remove_simple_block(config: str, opening_line: str) -> str:
    lines = config.splitlines()
    output: list[str] = []
    skipping = False
    for line in lines:
        if line == opening_line:
            skipping = True
            continue
        if skipping:
            if line.startswith("</"):
                skipping = False
            continue
        output.append(line)
    return "\n".join(output)
