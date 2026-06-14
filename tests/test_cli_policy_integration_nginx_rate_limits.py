from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from tests.nginx_logging_policy_helpers import write_policy
from tests.nginx_rate_limit_policy_helpers import (
    public_api_rate_limit_profile,
    rate_limits_policy_payload,
)
from webconf_audit.cli import app

runner = CliRunner()


def _write_rate_limit_policy(tmp_path: Path) -> Path:
    return write_policy(
        tmp_path,
        rate_limits_policy_payload(
            profiles=[public_api_rate_limit_profile()],
            requested_opt_in_tags=("policy-review",),
        ),
    )


def test_policy_validate_json_accepts_nginx_rate_limits_policy(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "policy",
            "validate",
            "--policy",
            str(_write_rate_limit_policy(tmp_path)),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["issues"] == []


def test_analyze_nginx_with_rate_limit_policy_emits_control_assessments(
    tmp_path: Path,
) -> None:
    policy_path = _write_rate_limit_policy(tmp_path)
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=api_per_ip:10m rate=5r/s;\n"
        "    limit_conn_zone $binary_remote_addr zone=api_conn_per_ip:10m;\n"
        "    limit_req_status 429;\n"
        "    limit_req_log_level notice;\n"
        "    limit_conn_status 429;\n"
        "    limit_conn_log_level notice;\n"
        "    server {\n"
        "        server_name api.example.test;\n"
        "        location /v1/ {\n"
        "            limit_req zone=api_per_ip burst=10;\n"
        "            limit_conn api_conn_per_ip 10;\n"
        "        }\n"
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
        "cis-nginx-5.2.4.connections-per-ip",
        "cis-nginx-5.2.5.requests-per-ip",
    }
    assert {
        entry["metadata"]["policy_section"]
        for entry in assessments
        if entry["control_id"] in {
            "cis-nginx-5.2.4.connections-per-ip",
            "cis-nginx-5.2.5.requests-per-ip",
        }
    } == {"nginx.rate_limits"}
    assert {
        entry["status"]
        for entry in assessments
        if entry["control_id"] in {
            "cis-nginx-5.2.4.connections-per-ip",
            "cis-nginx-5.2.5.requests-per-ip",
        }
    } == {"pass"}
