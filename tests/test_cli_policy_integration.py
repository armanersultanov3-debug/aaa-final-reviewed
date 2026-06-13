from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from webconf_audit.cli import app
from webconf_audit.models import AnalysisResult

runner = CliRunner()


def _policy_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "public-nginx-baseline",
        "policy_version": "2026.06",
        "title": "Public nginx baseline",
        "description": "Baseline policy for public nginx targets.",
        "defaults": {
            "disposition": "advisory",
            "evidence_expectation": "ledger-default",
            "include_unmapped_findings": True,
            "require_complete_execution_manifest": True,
        },
        "profiles": [
            {
                "profile_id": "nginx-production",
                "title": "Production nginx",
                "selectors": [
                    {
                        "mode": "local",
                        "server_type": "nginx",
                        "target_glob": "*nginx.conf",
                    }
                ],
                "requested_opt_in_tags": ["policy-review"],
                "sources": [
                    {
                        "source_id": "cis-nginx-3.0.0",
                        "disposition": "required",
                        "controls": [
                            {
                                "item_id": "nginx-4.1.12-http3-alt-svc",
                                "disposition": "review",
                                "evidence_expectation": "operator-review",
                                "required_rule_ids": ["nginx.http3_alt_svc_review"],
                                "rationale": "HTTP/3 exposure is an explicit architecture decision.",
                            }
                        ],
                    }
                ],
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


def _write_nginx_config(tmp_path: Path) -> Path:
    config = tmp_path / "nginx.conf"
    config.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        server_name example.test;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    return config


def test_policy_validate_json_succeeds(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["policy", "validate", "--policy", str(_write_policy(tmp_path)), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["valid"] is True
    assert payload["issues"] == []


def test_policy_show_json_resolves_target(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path)
    config_path = _write_nginx_config(tmp_path)

    result = runner.invoke(
        app,
        [
            "policy",
            "show",
            "--policy",
            str(policy_path),
            "--mode",
            "local",
            "--server-type",
            "nginx",
            "--target",
            str(config_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["resolved"]["profile_id"] == "nginx-production"
    assert payload["resolved"]["requested_opt_in_tags"] == ["policy-review"]


def test_analyze_nginx_with_policy_attaches_policy_and_manifest_metadata(
    tmp_path: Path,
) -> None:
    policy_path = _write_policy(tmp_path)
    config_path = _write_nginx_config(tmp_path)

    result = runner.invoke(
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

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    result_payload = payload["results"][0]
    metadata = result_payload["metadata"]

    assert metadata["audit_policy"]["profile_id"] == "nginx-production"
    assert metadata["audit_policy"]["requested_opt_in_tags"] == ["policy-review"]
    assert "nginx.http3_alt_svc_review" in metadata["rule_execution"]["selected_rule_ids"]
    assert "nginx.http3_alt_svc_review" in metadata["rule_execution"]["completed_rule_ids"]
    assert set(metadata["rule_execution"]) == {
        "schema_version",
        "registry_revision",
        "selected_rule_ids",
        "completed_rule_ids",
        "skipped_rules",
        "failed_rules",
    }


def test_analyze_nginx_without_policy_keeps_additive_null_policy_metadata(
    tmp_path: Path,
) -> None:
    config_path = _write_nginx_config(tmp_path)

    result = runner.invoke(
        app,
        ["analyze-nginx", str(config_path), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    metadata = payload["results"][0]["metadata"]
    assert metadata["audit_policy"] is None
    assert metadata["rule_execution"]["schema_version"] == 1


def test_analyze_nginx_with_invalid_policy_fails_before_analyzer_runs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    called = False

    def fake_analyze_nginx_config(config_path: str, **_kwargs: object) -> AnalysisResult:
        nonlocal called
        called = True
        return AnalysisResult(mode="local", target=config_path, server_type="nginx")

    bad_policy = tmp_path / ".webconf-audit-policy.yml"
    bad_policy.write_text("schema_version: 2\n", encoding="utf-8")

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(
        app,
        [
            "analyze-nginx",
            str(_write_nginx_config(tmp_path)),
            "--policy",
            str(bad_policy),
        ],
    )

    assert result.exit_code == 1
    assert called is False
    assert "policy_schema_unsupported" in (result.stdout + result.stderr)
