from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from webconf_audit.cli import app

runner = CliRunner()


def _policy_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "nginx-logging-contract",
        "policy_version": "2026.06",
        "title": "Nginx logging contract",
        "description": "Policy-backed logging requirements for nginx.",
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
                        "controls": [],
                    }
                ],
            }
        ],
        "nginx": {
            "logging": {
                "profiles": [
                    {
                        "profile_id": "public-server",
                        "applies_to": {"server_names": ["example.test"]},
                        "access": {
                            "required": True,
                            "allow_off": False,
                            "conditional": {
                                "mode": "forbid",
                                "allowed_conditions": [],
                            },
                            "destinations": {
                                "allowed": [
                                    {"kind": "file", "path": "/var/log/nginx/access.log"}
                                ],
                                "require_at_least_one_remote": False,
                                "allow_variable_paths": False,
                            },
                            "formats": {
                                "allowed_names": ["main_json"],
                                "require_escape": "json",
                                "required_field_groups": {
                                    "timestamp": ["$time_iso8601"],
                                    "client_ip": ["$remote_addr"],
                                    "request": ["$request"],
                                    "status": ["$status"],
                                    "correlation": ["$request_id"],
                                    "user_agent": ["$http_user_agent"],
                                },
                                "forbidden_variables": ["$http_authorization"],
                            },
                        },
                        "error": {
                            "required": True,
                            "require_explicit_destination": True,
                            "destinations": {
                                "allowed_kinds": ["file", "syslog", "stderr"],
                                "forbidden_paths": ["/dev/null"],
                            },
                            "threshold": {
                                "most_restrictive_allowed": "info",
                                "allow_debug": False,
                            },
                        },
                    }
                ],
                "unmatched_scopes": "indeterminate",
            }
        },
        "provenance": {
            "owner": "Security Engineering",
            "approved_on": "2026-06-12",
            "change_ref": "SEC-2026-206",
        },
    }


def _write_policy(tmp_path: Path) -> Path:
    path = tmp_path / ".webconf-audit-policy.yml"
    path.write_text(yaml.safe_dump(_policy_payload(), sort_keys=False), encoding="utf-8")
    return path


def test_policy_validate_json_accepts_nginx_logging_policy(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["policy", "validate", "--policy", str(_write_policy(tmp_path)), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["issues"] == []


def test_analyze_nginx_with_logging_policy_emits_control_assessments(
    tmp_path: Path,
) -> None:
    policy_path = _write_policy(tmp_path)
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        '    log_format main_json escape=json "$time_iso8601 $remote_addr $request $status $request_id $http_user_agent";\n'
        "    server {\n"
        "        server_name example.test;\n"
        "        access_log /var/log/nginx/access.log main_json;\n"
        "        error_log /var/log/nginx/error.log info;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

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
    assessments = payload["results"][0]["control_assessments"]
    assert {entry["control_id"] for entry in assessments} >= {
        "cis-nginx-3.1.detailed-access-logging",
        "cis-nginx-3.3.error-log-info-level",
    }
    assert {entry["metadata"]["logging_kind"] for entry in assessments} >= {
        "access",
        "error",
    }
