from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from webconf_audit.cli import app
from webconf_audit.models import AnalysisResult

runner = CliRunner()


def _policy_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "explicit-policy-cli",
        "policy_version": "2026.06",
        "title": "Explicit CLI policy",
        "description": "Policy fixture for CLI coverage.",
        "defaults": {
            "disposition": "advisory",
            "evidence_expectation": "ledger-default",
            "include_unmapped_findings": True,
            "require_complete_execution_manifest": True,
        },
        "profiles": [
            {
                "profile_id": "public-nginx",
                "title": "Public nginx",
                "selectors": [
                    {
                        "mode": "local",
                        "server_type": "nginx",
                        "target_glob": "*nginx.conf",
                    }
                ],
                "sources": [{"source_id": "cis-nginx-3.0.0"}],
            }
        ],
        "provenance": {
            "owner": "Security Engineering",
            "approved_on": "2026-06-12",
            "change_ref": "SEC-2026-104",
        },
    }


def _write_policy(tmp_path: Path, payload: dict[str, object] | None = None) -> Path:
    path = tmp_path / ".webconf-audit-policy.yml"
    path.write_text(
        yaml.safe_dump(payload or _policy_payload(), sort_keys=False),
        encoding="utf-8",
    )
    return path


def test_policy_validate_json_reports_invalid_schema(tmp_path: Path) -> None:
    policy_path = tmp_path / ".webconf-audit-policy.yml"
    policy_path.write_text("schema_version: 2\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["policy", "validate", "--policy", str(policy_path), "--format", "json"],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert payload["issues"][0]["code"] == "policy_schema_unsupported"


def test_policy_show_json_without_target_returns_parsed_policy(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["policy", "show", "--policy", str(_write_policy(tmp_path)), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["policy"]["policy_id"] == "explicit-policy-cli"
    assert payload["resolved"] is None
    assert payload["issues"] == []


def test_policy_show_json_load_error_wraps_policy_path_object(tmp_path: Path) -> None:
    missing_policy = tmp_path / ".webconf-audit-policy.yml"

    result = runner.invoke(
        app,
        ["policy", "show", "--policy", str(missing_policy), "--format", "json"],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["policy"] == {"path": str(missing_policy)}
    assert payload["resolved"] is None
    assert payload["issues"][0]["code"] == "policy_file_not_found"


def test_policy_show_json_validation_error_returns_policy_object(tmp_path: Path) -> None:
    payload = _policy_payload()
    payload["profiles"][0]["requested_opt_in_tags"] = ["unknown-opt-in"]

    result = runner.invoke(
        app,
        [
            "policy",
            "show",
            "--policy",
            str(_write_policy(tmp_path, payload)),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1, result.output
    response = json.loads(result.stdout)
    assert response["policy"]["policy_id"] == "explicit-policy-cli"
    assert response["resolved"] is None
    assert response["issues"][0]["code"] == "unknown_opt_in_tag"


@pytest.mark.parametrize(
    ("command", "target", "analyzer_attr"),
    [
        ("analyze-apache", "httpd.conf", "analyze_apache_config"),
        ("analyze-lighttpd", "lighttpd.conf", "analyze_lighttpd_config"),
        ("analyze-iis", "web.config", "analyze_iis_config"),
        ("analyze-external", "https://example.test", "analyze_external_target"),
    ],
)
def test_invalid_policy_blocks_other_analyzers_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    target: str,
    analyzer_attr: str,
) -> None:
    called = False

    def _fake_analyzer(target_value: str, **_kwargs: object) -> AnalysisResult:
        nonlocal called
        called = True
        mode = "external" if command == "analyze-external" else "local"
        server_type = None if command == "analyze-external" else command.removeprefix("analyze-")
        return AnalysisResult(mode=mode, target=target_value, server_type=server_type)

    bad_policy = tmp_path / ".webconf-audit-policy.yml"
    bad_policy.write_text("schema_version: 2\n", encoding="utf-8")
    target_value = target
    if command != "analyze-external":
        target_file = tmp_path / target
        target_file.write_text("# placeholder\n", encoding="utf-8")
        target_value = str(target_file)

    monkeypatch.setattr(f"webconf_audit.cli.{analyzer_attr}", _fake_analyzer)

    result = runner.invoke(
        app,
        [command, target_value, "--policy", str(bad_policy)],
    )

    assert result.exit_code == 1
    assert called is False
    assert "policy_schema_unsupported" in (result.stdout + result.stderr)
