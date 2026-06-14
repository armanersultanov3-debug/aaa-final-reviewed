from __future__ import annotations

from pathlib import Path

import yaml

from webconf_audit.audit_policy import AuditTarget, load_audit_policy, resolve_audit_policy
from webconf_audit.coverage_ledger import load_coverage_ledger
from webconf_audit.local.nginx import analyze_nginx_config


def _policy_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "nginx-reverse-proxy-contract",
        "policy_version": "2026.06",
        "title": "Nginx reverse proxy contract",
        "description": "Route-level reverse proxy header requirements.",
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
            "reverse_proxy_headers": {
                "profiles": [
                    {
                        "profile_id": "proxy-api",
                        "applies_to": {
                            "upstream_families": ["proxy"],
                            "server_names": ["example.test"],
                            "location_patterns": ["/api/"],
                        },
                        "request_headers": {
                            "required": {
                                "X-Forwarded-For": {
                                    "any_of": ["$proxy_add_x_forwarded_for", "$remote_addr"]
                                },
                                "X-Real-IP": {"any_of": ["$remote_addr"]},
                                "X-Forwarded-Proto": {"any_of": ["$scheme"]},
                            },
                            "host": {
                                "allowed_values": ["$host", "$proxy_host"],
                                "allow_fixed_literals": True,
                            },
                            "forbidden_client_variables": [
                                "$http_x_forwarded_for",
                                "$http_x_real_ip",
                                "$http_host",
                            ],
                        },
                        "response_headers": {
                            "must_hide": ["X-Powered-By"],
                            "must_not_pass": ["Server"],
                            "allow_explicit_pass": [],
                        },
                    }
                ],
                "unmatched_routes": "indeterminate",
            }
        },
        "provenance": {
            "owner": "Security Engineering",
            "approved_on": "2026-06-12",
            "change_ref": "SEC-2026-204",
        },
    }


def _write_policy(tmp_path: Path, payload: dict[str, object]) -> Path:
    policy_path = tmp_path / ".webconf-audit-policy.yml"
    policy_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return policy_path


def _resolved_policy(tmp_path: Path, payload: dict[str, object]):
    ledger = load_coverage_ledger()
    policy = load_audit_policy(_write_policy(tmp_path, payload))
    return resolve_audit_policy(
        policy,
        AuditTarget(
            mode="local",
            server_type="nginx",
            target=str(tmp_path / "nginx.conf"),
        ),
        ledger,
    )


def _assessment_by_id(result, control_id: str):
    return next(assessment for assessment in result.control_assessments if assessment.control_id == control_id)


def test_reverse_proxy_policy_local_header_list_replaces_parent_list(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "    proxy_set_header X-Real-IP $remote_addr;\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location /api/ {\n"
        "            proxy_set_header X-Forwarded-Proto $scheme;\n"
        "            proxy_set_header Host $host;\n"
        "            proxy_hide_header X-Powered-By;\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(tmp_path, _policy_payload()),
    )

    source_identity = _assessment_by_id(result, "cis-nginx-3.4.proxy-source-identity")
    assert source_identity.status == "fail"
    assert "nginx.proxy_missing_source_ip_headers" in {finding.rule_id for finding in result.findings}


def test_reverse_proxy_policy_illegal_if_context_does_not_override_parent_route(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location /api/ {\n"
        "            if ($request_method = GET) {\n"
        "                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "            }\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(tmp_path, _policy_payload()),
    )

    source_identity = _assessment_by_id(result, "cis-nginx-3.4.proxy-source-identity")
    assert source_identity.status == "fail"
    unsupported = source_identity.metadata["unsupported_or_dynamic_evidence"]
    assert any(entry["reason"] == "illegal-context" for entry in unsupported)


def test_reverse_proxy_policy_missing_include_yields_indeterminate(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location /api/ {\n"
        "            include missing.conf;\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(tmp_path, _policy_payload()),
    )

    source_identity = _assessment_by_id(result, "cis-nginx-3.4.proxy-source-identity")
    assert source_identity.status == "indeterminate"


def test_reverse_proxy_policy_response_filters_cover_all_supported_families(
    tmp_path: Path,
) -> None:
    payload = _policy_payload()
    payload["nginx"]["reverse_proxy_headers"]["profiles"] = [  # type: ignore[index]
        {
            "profile_id": "proxy-route",
            "applies_to": {
                "upstream_families": ["proxy"],
                "server_names": ["example.test"],
                "location_patterns": ["/proxy/"],
            },
            "request_headers": {
                "required": {},
                "host": {"allowed_values": ["$host"], "allow_fixed_literals": False},
                "forbidden_client_variables": ["$http_host"],
            },
            "response_headers": {
                "must_hide": ["X-Powered-By"],
                "must_not_pass": ["Server"],
                "allow_explicit_pass": [],
            },
        },
        {
            "profile_id": "fastcgi-route",
            "applies_to": {
                "upstream_families": ["fastcgi"],
                "server_names": ["example.test"],
                "location_patterns": ["/fastcgi/"],
            },
            "request_headers": {
                "required": {},
                "host": {"allowed_values": ["$host$is_request_port$request_port"], "allow_fixed_literals": False},
                "forbidden_client_variables": ["$http_host"],
            },
            "response_headers": {
                "must_hide": ["X-Powered-By"],
                "must_not_pass": ["Server"],
                "allow_explicit_pass": [],
            },
        },
        {
            "profile_id": "grpc-route",
            "applies_to": {
                "upstream_families": ["grpc"],
                "server_names": ["example.test"],
                "location_patterns": ["/grpc/"],
            },
            "request_headers": {
                "required": {},
                "host": {"allowed_values": ["$host"], "allow_fixed_literals": False},
                "forbidden_client_variables": ["$http_host"],
            },
            "response_headers": {
                "must_hide": ["X-Powered-By"],
                "must_not_pass": ["Server"],
                "allow_explicit_pass": [],
            },
        },
        {
            "profile_id": "uwsgi-route",
            "applies_to": {
                "upstream_families": ["uwsgi"],
                "server_names": ["example.test"],
                "location_patterns": ["/uwsgi/"],
            },
            "request_headers": {
                "required": {},
                "host": {"allowed_values": ["$host$is_request_port$request_port"], "allow_fixed_literals": False},
                "forbidden_client_variables": ["$http_host"],
            },
            "response_headers": {
                "must_hide": ["X-Powered-By"],
                "must_not_pass": ["Server"],
                "allow_explicit_pass": [],
            },
        },
    ]
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location /proxy/ {\n"
        "            proxy_set_header Host $host;\n"
        "            proxy_hide_header X-Powered-By;\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "        location /fastcgi/ {\n"
        "            fastcgi_param HTTP_HOST $host$is_request_port$request_port;\n"
        "            fastcgi_hide_header X-Powered-By;\n"
        "            fastcgi_pass_header Server;\n"
        "            fastcgi_pass backend;\n"
        "        }\n"
        "        location /grpc/ {\n"
        "            grpc_set_header Host $host;\n"
        "            grpc_hide_header X-Powered-By;\n"
        "            grpc_pass grpc://backend;\n"
        "        }\n"
        "        location /uwsgi/ {\n"
        "            uwsgi_param HTTP_HOST $host$is_request_port$request_port;\n"
        "            uwsgi_hide_header X-Powered-By;\n"
        "            uwsgi_pass backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(tmp_path, payload),
    )

    disclosure = [
        assessment
        for assessment in result.control_assessments
        if assessment.control_id == "cis-nginx-2.5.4.proxy-response-disclosure"
    ]
    statuses_by_family = {
        assessment.metadata["upstream_family"]: assessment.status
        for assessment in disclosure
    }

    assert statuses_by_family["proxy"] == "pass"
    assert statuses_by_family["fastcgi"] == "fail"
    assert statuses_by_family["grpc"] == "pass"
    assert statuses_by_family["uwsgi"] == "fail"


def test_reverse_proxy_policy_records_dynamic_response_header_source_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location /api/ {\n"
        "            proxy_set_header Host $host;\n"
        "            proxy_hide_header $backend_header;\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(tmp_path, _policy_payload()),
    )

    disclosure = _assessment_by_id(result, "cis-nginx-2.5.4.proxy-response-disclosure")
    unsupported = disclosure.metadata["unsupported_or_dynamic_evidence"]
    dynamic_entry = next(
        entry
        for entry in unsupported
        if entry["reason"] == "dynamic-header-name"
    )
    assert dynamic_entry["source"]["line"] == 7
