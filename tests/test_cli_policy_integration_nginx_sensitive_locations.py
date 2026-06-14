from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from tests.nginx_sensitive_location_policy_helpers import (
    sensitive_location_entry,
    sensitive_locations_policy_payload,
    write_policy,
)
from webconf_audit.cli import app

runner = CliRunner()


def _write_sensitive_location_policy(tmp_path: Path) -> Path:
    return write_policy(
        tmp_path,
        sensitive_locations_policy_payload(
            catalog=[sensitive_location_entry()],
            requested_opt_in_tags=("policy-review",),
        ),
    )


def test_policy_validate_json_accepts_nginx_sensitive_locations_policy(
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "policy",
            "validate",
            "--policy",
            str(_write_sensitive_location_policy(tmp_path)),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["issues"] == []


def test_analyze_nginx_with_sensitive_location_policy_emits_control_assessments(
    tmp_path: Path,
) -> None:
    policy_path = _write_sensitive_location_policy(tmp_path)
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location ^~ /admin/ {\n"
        "            allow 10.20.0.0/16;\n"
        "            deny all;\n"
        "            auth_request /authz;\n"
        "            satisfy all;\n"
        "        }\n"
        "        location = /authz {\n"
        "            internal;\n"
        "            return 204;\n"
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
        "policy.nginx.sensitive-location.admin-console",
        "cis-nginx-5.1.1.sensitive-ip-filters",
    }
    policy_assessments = [
        entry
        for entry in assessments
        if entry["control_id"].startswith("policy.nginx.sensitive-location.")
        or entry["control_id"] in {
            "cis-nginx-5.1.1.sensitive-ip-filters",
            "asvs-5.0.0-v13.4.5.sensitive-endpoint-exposure",
        }
    ]
    assert policy_assessments
    assert {
        entry["metadata"]["policy_section"]
        for entry in policy_assessments
    } == {"nginx.sensitive_locations"}
