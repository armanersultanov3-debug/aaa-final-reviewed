from __future__ import annotations

import json

from typer.testing import CliRunner

from webconf_audit.cli import app
from webconf_audit.models import AnalysisResult, Finding, SourceLocation
from webconf_audit.report import JsonFormatter, ReportData, TextFormatter


def _finding(
    *,
    rule_id: str,
    title: str,
    severity: str = "low",
    line: int,
    metadata: dict[str, object] | None = None,
    effective_cause_key: tuple[str, ...] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,  # type: ignore[arg-type]
        description="desc",
        recommendation="rec",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path="/etc/apache2/apache2.conf",
            line=line,
        ),
        metadata=metadata or {},
        effective_cause_key=effective_cause_key,
    )


def _report(*findings: Finding) -> ReportData:
    return ReportData(
        results=[
            AnalysisResult(
                mode="local",
                target="/etc/apache2/apache2.conf",
                server_type="apache",
                findings=list(findings),
            )
        ]
    )


def test_text_grouping_merges_findings_by_effective_cause() -> None:
    cause_key = ("/etc/apache2/apache2.conf", "42")
    report = _report(
        _finding(
            rule_id="apache.error_log_unsafe_destination",
            title="ErrorLog destination is unsafe",
            line=42,
            metadata={"affected_scopes": ["alpha.test", "beta.test"]},
            effective_cause_key=cause_key,
        ),
        _finding(
            rule_id="apache.log_level_too_restrictive",
            title="LogLevel is too restrictive",
            line=42,
            metadata={"affected_scopes": ["beta.test", "gamma.test"]},
            effective_cause_key=cause_key,
        ),
    )

    out = TextFormatter(group_by_cause=True).format(report)

    assert "=== CAUSE GROUPS (1) ===" in out
    assert "cause: /etc/apache2/apache2.conf:42" in out
    assert "affected scopes (3): alpha.test, beta.test, gamma.test" in out
    assert "[apache.error_log_unsafe_destination] ErrorLog destination is unsafe" in out
    assert "[apache.log_level_too_restrictive] LogLevel is too restrictive" in out


def test_text_grouping_keeps_uncausal_findings_individual() -> None:
    report = _report(
        _finding(
            rule_id="apache.error_log_unsafe_destination",
            title="ErrorLog destination is unsafe",
            line=42,
            metadata={"affected_scopes": ["alpha.test"]},
            effective_cause_key=("/etc/apache2/apache2.conf", "42"),
        ),
        _finding(
            rule_id="apache.missing_log_format",
            title="CustomLog references undefined LogFormat",
            line=90,
        ),
    )

    out = TextFormatter(group_by_cause=True).format(report)

    assert "=== CAUSE GROUPS (1) ===" in out
    assert "=== UNCAUSAL FINDINGS (1) ===" in out
    assert "[apache.missing_log_format] CustomLog references undefined LogFormat" in out


def test_json_grouping_adds_cause_groups_payload() -> None:
    report = _report(
        _finding(
            rule_id="apache.error_log_unsafe_destination",
            title="ErrorLog destination is unsafe",
            line=42,
            metadata={"affected_scopes": ["alpha.test", "beta.test"]},
            effective_cause_key=("/etc/apache2/apache2.conf", "42"),
        )
    )

    parsed = json.loads(JsonFormatter(group_by_cause=True).format(report))

    assert parsed["cause_groups"][0]["cause_key"] == [
        "/etc/apache2/apache2.conf",
        "42",
    ]
    grouped_finding = parsed["cause_groups"][0]["findings"][0]
    assert grouped_finding["target"] == "/etc/apache2/apache2.conf"
    assert grouped_finding["rule_id"] == "apache.error_log_unsafe_destination"
    assert grouped_finding["effective_cause_key"] == [
        "/etc/apache2/apache2.conf",
        "42",
    ]
    assert grouped_finding["metadata"]["affected_scopes"] == [
        "alpha.test",
        "beta.test",
    ]
    assert grouped_finding["fingerprint"] == parsed["findings"][0]["fingerprint"]


def test_json_grouping_preserves_flat_findings_array() -> None:
    report = _report(
        _finding(
            rule_id="apache.error_log_unsafe_destination",
            title="ErrorLog destination is unsafe",
            line=42,
            effective_cause_key=("/etc/apache2/apache2.conf", "42"),
        ),
        _finding(
            rule_id="apache.missing_log_format",
            title="CustomLog references undefined LogFormat",
            line=90,
        ),
    )

    parsed = json.loads(JsonFormatter(group_by_cause=True).format(report))

    assert [finding["rule_id"] for finding in parsed["findings"]] == [
        "apache.error_log_unsafe_destination",
        "apache.missing_log_format",
    ]
    assert len(parsed["cause_groups"]) == 1
    assert parsed["cause_groups"][0]["findings"][0]["rule_id"] == (
        "apache.error_log_unsafe_destination"
    )


def test_text_grouping_uses_scope_name_when_affected_scopes_is_empty() -> None:
    report = _report(
        _finding(
            rule_id="apache.log_level_too_restrictive",
            title="LogLevel is too restrictive",
            line=42,
            metadata={"scope_name": "beta.test", "affected_scopes": []},
            effective_cause_key=("/etc/apache2/apache2.conf", "42"),
        )
    )

    out = TextFormatter(group_by_cause=True).format(report)

    assert "affected scopes (1): beta.test" in out


def test_cli_warns_and_uses_last_grouping_flag(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.missing_hsts_header",
                    title="Missing HSTS header",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/sites/app.conf",
                        line=3,
                    ),
                    effective_cause_key=("/sites/app.conf", "3"),
                ),
                Finding(
                    rule_id="nginx.missing_hsts_header",
                    title="Missing HSTS header",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/sites/app.conf",
                        line=27,
                    ),
                    effective_cause_key=("/sites/app.conf", "27"),
                ),
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = CliRunner().invoke(
        app,
        ["analyze-nginx", "nginx.conf", "--group-by-cause", "--group-repeated"],
    )

    assert result.exit_code == 0
    assert "mutually exclusive; using the last one provided." in result.output
    assert "findings: 2 repeated" in result.output
    assert "=== CAUSE GROUPS" not in result.output
