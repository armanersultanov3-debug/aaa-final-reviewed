from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from tests.nginx_response_header_policy_helpers import (
    response_headers_policy_payload,
    response_route,
)
from webconf_audit.cli import app

runner = CliRunner()


def test_analyze_nginx_with_response_header_policy_emits_control_assessments(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / ".webconf-audit-policy.yml"
    policy_path.write_text(
        yaml.safe_dump(
            response_headers_policy_payload(
                routes=[
                    response_route(
                        route_id="app-html",
                        server_names=("www.example.test",),
                        profile="browser-document",
                        declared_location={"modifier": "prefix", "pattern": "/"},
                    )
                ]
            ),
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        server_name www.example.test;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        location / {\n"
        "            add_header Content-Security-Policy \"object-src 'none'; base-uri 'none'; script-src 'nonce-$csp_nonce'; frame-ancestors 'none'; report-to csp\" always;\n"
        "            add_header Reporting-Endpoints 'csp=\"https://reports.example.test/csp\"' always;\n"
        "            add_header Referrer-Policy no-referrer always;\n"
        "            add_header X-Content-Type-Options nosniff always;\n"
        "            add_header Cross-Origin-Opener-Policy same-origin always;\n"
        "            add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
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
        "cis-nginx-5.3.2.csp",
        "cis-nginx-5.3.3.referrer-policy",
        "asvs-5.0.0-v3.4.3.csp-quality",
    }
