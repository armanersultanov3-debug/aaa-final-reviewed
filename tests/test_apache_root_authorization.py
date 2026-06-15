from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.apache.include import resolve_includes
from webconf_audit.local.apache.parser import parse_apache_config
from webconf_audit.local.apache.authorization import evaluate_root_authorization


def _root_block(*lines: str) -> str:
    return "\n".join(("<Directory />", *lines, "</Directory>"))


def _parse_with_includes(
    tmp_path: Path,
    config_text: str,
    *,
    file_name: str = "httpd.conf",
):
    config_path = tmp_path / file_name
    config_path.write_text(config_text, encoding="utf-8")
    ast = parse_apache_config(config_text, file_path=str(config_path))
    issues = resolve_includes(ast, config_path)
    return config_path, ast, issues


def _rule_findings(result) -> list:
    return [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.os_root_access_not_denied"
    ]


def _rule_issues(result) -> list:
    return [
        issue
        for issue in result.issues
        if issue.code == "apache_root_authorization_indeterminate"
    ]


def test_evaluate_root_authorization_accepts_modern_deny_all_root_block(
    tmp_path: Path,
) -> None:
    _config_path, ast, issues = _parse_with_includes(
        tmp_path,
        _root_block("    Require all denied"),
    )

    assessment = evaluate_root_authorization(ast, issues=issues)

    assert assessment.include_graph_complete is True
    assert len(assessment.root_blocks) == 1
    assert assessment.effective.decision == "deny_all"
    assert assessment.effective.syntax == "modern"


def test_evaluate_root_authorization_accepts_requireall_with_denied_child(
    tmp_path: Path,
) -> None:
    _config_path, ast, issues = _parse_with_includes(
        tmp_path,
        _root_block(
            "    <RequireAll>",
            "        Require all denied",
            "        Require all granted",
            "    </RequireAll>",
        ),
    )

    assessment = evaluate_root_authorization(ast, issues=issues)

    assert assessment.effective.decision == "deny_all"
    assert assessment.effective.syntax == "modern"


def test_evaluate_root_authorization_reports_requireany_granted_branch_as_permissive(
    tmp_path: Path,
) -> None:
    _config_path, ast, issues = _parse_with_includes(
        tmp_path,
        _root_block(
            "    <RequireAny>",
            "        Require all denied",
            "        Require all granted",
            "    </RequireAny>",
        ),
    )

    assessment = evaluate_root_authorization(ast, issues=issues)

    assert assessment.effective.decision == "not_deny_all"
    assert assessment.effective.syntax == "modern"


def test_evaluate_root_authorization_accepts_legacy_allow_deny_default_deny(
    tmp_path: Path,
) -> None:
    _config_path, ast, issues = _parse_with_includes(
        tmp_path,
        _root_block(
            "    Order Allow,Deny",
            "    Deny from all",
        ),
    )

    assessment = evaluate_root_authorization(ast, issues=issues)

    assert assessment.effective.decision == "deny_all"
    assert assessment.effective.syntax == "legacy"


def test_evaluate_root_authorization_reports_legacy_deny_allow_default_allow(
    tmp_path: Path,
) -> None:
    _config_path, ast, issues = _parse_with_includes(
        tmp_path,
        _root_block("    Order Deny,Allow"),
    )

    assessment = evaluate_root_authorization(ast, issues=issues)

    assert assessment.effective.decision == "not_deny_all"
    assert assessment.effective.syntax == "legacy"


def test_analyze_apache_config_reports_missing_root_baseline_when_complete(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text("ServerTokens Prod\n", encoding="utf-8")

    result = analyze_apache_config(str(config_path))

    findings = _rule_findings(result)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(config_path)
    assert not _rule_issues(result)


def test_analyze_apache_config_reports_permissive_root_authorization(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _root_block("    Require all granted"),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    findings = _rule_findings(result)
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(config_path)
    assert findings[0].location.line == 2
    assert not _rule_issues(result)


def test_analyze_apache_config_reports_auth_merging_or_as_permissive_override(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            (
                _root_block("    Require all denied"),
                _root_block(
                    "    AuthMerging Or",
                    "    Require all granted",
                ),
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    findings = _rule_findings(result)
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(config_path)
    assert findings[0].location.line == 6


def test_analyze_apache_config_keeps_auth_merging_and_deny_all_baseline(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            (
                _root_block("    Require all denied"),
                _root_block(
                    "    AuthMerging And",
                    "    Require all granted",
                ),
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert not _rule_findings(result)
    assert not _rule_issues(result)


def test_analyze_apache_config_reports_mixed_root_authorization_as_indeterminate(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _root_block(
            "    Require all denied",
            "    Order Allow,Deny",
            "    Deny from all",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert not _rule_findings(result)
    issues = _rule_issues(result)
    assert len(issues) == 1
    assert issues[0].location is not None
    assert issues[0].location.file_path == str(config_path)


def test_analyze_apache_config_reports_dynamic_if_root_authorization_as_indeterminate(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _root_block(
            "    Require all denied",
            '    <If "%{REQUEST_URI} == \'/health\'">',
            "        Require all granted",
            "    </If>",
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert not _rule_findings(result)
    assert len(_rule_issues(result)) == 1


def test_analyze_apache_config_reports_missing_include_as_indeterminate_for_root_baseline(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text('Include "missing.conf"\n', encoding="utf-8")

    result = analyze_apache_config(str(config_path))

    assert not _rule_findings(result)
    assert {issue.code for issue in result.issues} >= {
        "apache_include_not_found",
        "apache_root_authorization_indeterminate",
    }


def test_analyze_apache_config_reports_require_expr_as_indeterminate(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _root_block('    Require expr "%{REMOTE_ADDR} =~ /127\\.0\\.0\\.1/"'),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert not _rule_findings(result)
    assert len(_rule_issues(result)) == 1
