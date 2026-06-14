from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from webconf_audit.cli import app

runner = CliRunner()


def _write_policy(tmp_path: Path) -> Path:
    payload = {
        "schema_version": 1,
        "policy_id": "assessment-cli-policy",
        "policy_version": "2026.06",
        "title": "Assessment CLI policy",
        "description": "Policy fixture for assessment CLI coverage.",
        "defaults": {
            "disposition": "required",
            "evidence_expectation": "ledger-default",
            "include_unmapped_findings": True,
            "require_complete_execution_manifest": True,
        },
        "profiles": [
            {
                "profile_id": "nginx-target",
                "title": "Nginx target",
                "selectors": [
                    {
                        "mode": "local",
                        "server_type": "nginx",
                        "target_glob": "*nginx.conf",
                    }
                ],
                "sources": [
                    {
                        "source_id": "owasp-asvs-5.0.0",
                        "controls": [
                            {
                                "item_id": "asvs-3.4.5-referrer-policy",
                                "disposition": "required",
                                "evidence_expectation": "ledger-default",
                                "required_rule_ids": ["universal.missing_referrer_policy"],
                                "rationale": "Referrer-Policy is required.",
                            }
                        ],
                    }
                ],
            }
        ],
        "provenance": {
            "owner": "Security Engineering",
            "approved_on": "2026-06-14",
            "change_ref": "SEC-CTRL-ASSESS-CLI",
        },
    }
    path = tmp_path / ".webconf-audit-policy.yml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _write_nginx_config(tmp_path: Path) -> Path:
    config = tmp_path / "edge-nginx.conf"
    config.write_text(
        "events {}\n"
        "http {\n"
        "  server {\n"
        "    listen 443 ssl;\n"
        "    server_name example.test;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    return config


def test_assess_cli_json_reports_legacy_input_error(tmp_path: Path) -> None:
    report_path = tmp_path / "legacy.json"
    report_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-06-14T00:00:00Z",
                "summary": {"total_findings": 0, "total_issues": 0, "suppressed_findings": 0, "suppressed_duplicates": 0, "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "by_mode": {}, "by_server_type": {}, "targets_analyzed": []},
                "results": [],
                "findings": [],
                "issues": [],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["assess", "--report", str(report_path), "--format", "json"],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["assessment"] is None
    assert payload["issues"][0]["code"] == "unassessable_legacy_report"


def test_assess_cli_real_analysis_flow_can_gate_and_write_output(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path)
    config_path = _write_nginx_config(tmp_path)
    analysis_path = tmp_path / "analysis.json"
    assessment_path = tmp_path / "assessment.json"

    analyze = runner.invoke(
        app,
        [
            "analyze-nginx",
            str(config_path),
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )
    assert analyze.exit_code == 0, analyze.output
    analysis_path.write_text(analyze.stdout, encoding="utf-8")

    assess = runner.invoke(
        app,
        [
            "assess",
            "--report",
            str(analysis_path),
            "--policy",
            str(policy_path),
            "--format",
            "json",
            "--output",
            str(assessment_path),
            "--fail-on",
            "fail,indeterminate",
        ],
    )

    assert assess.exit_code == 3, assess.output
    assert assessment_path.exists()
    payload = json.loads(assessment_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["summary"]["failed"] >= 1
    assert any(
        control["status"] == "fail"
        for source in payload["sources"]
        for control in source["controls"]
    )


def test_assess_cli_rejects_unknown_source_filter(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path)
    config_path = _write_nginx_config(tmp_path)
    analysis_path = tmp_path / "analysis.json"
    analyze = runner.invoke(
        app,
        [
            "analyze-nginx",
            str(config_path),
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )
    assert analyze.exit_code == 0, analyze.output
    analysis_path.write_text(analyze.stdout, encoding="utf-8")

    assess = runner.invoke(
        app,
        [
            "assess",
            "--report",
            str(analysis_path),
            "--format",
            "json",
            "--source",
            "unknown-source-id",
        ],
    )

    assert assess.exit_code == 1, assess.output
    payload = json.loads(assess.stdout)
    assert payload["issues"][0]["code"] == "unknown_source_filter"


def test_assess_cli_invalid_fail_on_status_uses_usage_error(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text("{}", encoding="utf-8")

    result = runner.invoke(
        app,
        ["assess", "--report", str(report_path), "--fail-on", "definitely-not-a-status"],
    )

    assert result.exit_code == 2
    assert "invalid_fail_on_status" in result.output
