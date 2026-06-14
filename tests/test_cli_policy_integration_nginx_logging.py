from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from tests.nginx_logging_policy_helpers import (
    logging_policy_payload,
    server_logging_profile,
    write_policy,
)
from webconf_audit.cli import app

runner = CliRunner()


def _write_policy(tmp_path: Path) -> Path:
    return write_policy(
        tmp_path,
        logging_policy_payload(
            logging_profiles=[server_logging_profile()],
            requested_opt_in_tags=("policy-review",),
        ),
    )


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
