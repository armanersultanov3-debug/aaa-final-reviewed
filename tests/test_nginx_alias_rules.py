from __future__ import annotations

from tests.nginx_helpers import Path, analyze_nginx_config


def test_analyze_nginx_config_reports_alias_traversal_classic_pattern(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location /static {\n    alias /srv/static/;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert any(
        finding.rule_id == "nginx.alias_traversal_classic_pattern"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_alias_traversal_classic_pattern_for_matching_slashes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location /static/ {\n    alias /srv/static/;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.alias_traversal_classic_pattern"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_alias_traversal_classic_pattern_for_exact_match_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location = /static {\n    alias /srv/static/;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.alias_traversal_classic_pattern"
        for finding in result.findings
    )
