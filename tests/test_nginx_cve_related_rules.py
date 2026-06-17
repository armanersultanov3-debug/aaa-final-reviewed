from tests.nginx_helpers import (
    Path,
    _http_block,
    _line_number,
    _safe_server_block,
    analyze_nginx_config,
)


def _analyze_config(
    tmp_path: Path,
    config_text: str,
    *,
    enable_policy_review: bool = False,
):
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(config_text, encoding="utf-8")
    result = analyze_nginx_config(
        str(config_path),
        enable_policy_review=enable_policy_review,
    )
    assert result.issues == []
    return result.findings


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def _single_finding(findings, rule_id: str):
    matches = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matches) == 1
    return matches[0]


def test_dav_copy_move_with_alias_prefix_location_is_reported(tmp_path: Path):
    config = _http_block(
        _safe_server_block(
            "location /files/ {",
            "    alias /srv/files/;",
            "    dav_methods PUT DELETE MKCOL COPY MOVE;",
            "}",
        )
    )

    finding = _single_finding(
        _analyze_config(tmp_path, config),
        "nginx.dav_move_copy_alias_prefix_location",
    )

    assert "CVE-2026-27654" in finding.description
    assert finding.location is not None
    assert finding.location.line == _line_number(config, "dav_methods")


def test_dav_without_copy_or_move_is_not_reported(tmp_path: Path):
    config = _http_block(
        _safe_server_block(
            "location /files/ {",
            "    alias /srv/files/;",
            "    dav_methods PUT DELETE MKCOL;",
            "}",
        )
    )

    assert "nginx.dav_move_copy_alias_prefix_location" not in _rule_ids(
        _analyze_config(tmp_path, config)
    )


def test_rewrite_unnamed_capture_question_mark_review_is_opt_in(tmp_path: Path):
    config = _http_block(
        _safe_server_block(
            "rewrite ^/legacy/(.*)$ /new/$1? permanent;",
            "set $legacy_marker $arg_legacy_marker;",
        )
    )

    default_findings = _analyze_config(tmp_path, config)
    assert "nginx.rewrite_unnamed_capture_question_mark_review" not in _rule_ids(
        default_findings
    )

    finding = _single_finding(
        _analyze_config(tmp_path, config, enable_policy_review=True),
        "nginx.rewrite_unnamed_capture_question_mark_review",
    )

    assert "CVE-2026-42945" in finding.description
    assert finding.location is not None
    assert finding.location.line == _line_number(config, "rewrite ^/legacy")


def test_rewrite_named_capture_question_mark_review_is_not_reported(tmp_path: Path):
    config = _http_block(
        _safe_server_block(
            "rewrite ^/legacy/(?<path>.*)$ /new/$path? permanent;",
            "set $legacy_marker $arg_legacy_marker;",
        )
    )

    assert "nginx.rewrite_unnamed_capture_question_mark_review" not in _rule_ids(
        _analyze_config(tmp_path, config, enable_policy_review=True)
    )
