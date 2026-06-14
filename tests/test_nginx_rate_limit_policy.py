from __future__ import annotations

from pathlib import Path

from tests.nginx_rate_limit_policy_helpers import (
    public_api_rate_limit_profile,
    rate_limits_policy_payload,
    resolved_rate_limit_policy,
)
from webconf_audit.local.nginx import analyze_nginx_config


def _assessment(result, control_id: str, *, profile_id: str, route_scope_id: str | None = None):
    matches = [
        entry
        for entry in result.control_assessments
        if entry.control_id == control_id
        and entry.metadata["profile_id"] == profile_id
        and (
            route_scope_id is None
            or entry.scope.route_scope_id == route_scope_id
        )
    ]
    assert matches, (control_id, profile_id, route_scope_id)
    assert len(matches) == 1, (control_id, profile_id, route_scope_id)
    return matches[0]


def test_rate_limit_policy_emits_separate_request_and_connection_assessments(
    tmp_path: Path,
) -> None:
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
    policy = resolved_rate_limit_policy(
        tmp_path,
        rate_limits_policy_payload(
            profiles=[public_api_rate_limit_profile()],
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    request = _assessment(
        result,
        "cis-nginx-5.2.5.requests-per-ip",
        profile_id="public-api",
    )
    connection = _assessment(
        result,
        "cis-nginx-5.2.4.connections-per-ip",
        profile_id="public-api",
    )

    assert request.status == "pass"
    assert connection.status == "pass"
    assert request.metadata["policy_section"] == "nginx.rate_limits"
    assert request.metadata["complete"] is True
    assert request.metadata["unsupported_evidence"] == []
    assert request.metadata["request_limits"][0]["zone_name"] == "api_per_ip"
    assert connection.metadata["connection_limits"][0]["zone_name"] == "api_conn_per_ip"


def test_rate_limit_policy_is_route_aware_and_does_not_credit_health_route_for_public_api(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=api_per_ip:10m rate=5r/s;\n"
        "    limit_conn_zone $binary_remote_addr zone=api_conn_per_ip:10m;\n"
        "    server {\n"
        "        server_name api.example.test;\n"
        "        location = /healthz {\n"
        "            limit_req zone=api_per_ip burst=1;\n"
        "            limit_conn api_conn_per_ip 1;\n"
        "        }\n"
        "        location /v1/ { }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_rate_limit_policy(
        tmp_path,
        rate_limits_policy_payload(
            profiles=[public_api_rate_limit_profile()],
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    request = _assessment(
        result,
        "cis-nginx-5.2.5.requests-per-ip",
        profile_id="public-api",
    )
    connection = _assessment(
        result,
        "cis-nginx-5.2.4.connections-per-ip",
        profile_id="public-api",
    )

    assert request.status == "fail"
    assert connection.status == "fail"


def test_rate_limit_policy_marks_unknown_zone_definition_indeterminate_without_hiding_finding(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=api_per_ip:10m rate=5r/s;\n"
        "    server {\n"
        "        server_name api.example.test;\n"
        "        location /v1/ {\n"
        "            limit_req zone=missing_req burst=10;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_rate_limit_policy(
        tmp_path,
        rate_limits_policy_payload(
            profiles=[
                public_api_rate_limit_profile(
                    request={
                        "required": True,
                        "accepted_zones": ["api_per_ip"],
                        "require_all_zones": False,
                        "additional_zones": "allow",
                        "burst": {"min": 0, "max": 20},
                        "delay_mode": "default",
                        "dry_run": False,
                        "allowed_rejection_statuses": [429, 503],
                        "allowed_log_levels": ["notice", "warn", "error"],
                    },
                    connection={"required": False},
                )
            ],
        ),
    )

    no_policy_result = analyze_nginx_config(str(config_path))
    policy_result = analyze_nginx_config(str(config_path), policy=policy)

    assert {finding.rule_id for finding in policy_result.findings} == {
        finding.rule_id for finding in no_policy_result.findings
    }
    assert "nginx.limit_req_unknown_zone" in {
        finding.rule_id for finding in policy_result.findings
    }
    request = _assessment(
        policy_result,
        "cis-nginx-5.2.5.requests-per-ip",
        profile_id="public-api",
    )
    assert request.status == "indeterminate"


def test_rate_limit_policy_fails_dry_run_and_wrong_status(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=api_per_ip:10m rate=5r/s;\n"
        "    limit_req_dry_run on;\n"
        "    limit_req_status 503;\n"
        "    limit_req_log_level error;\n"
        "    server {\n"
        "        server_name api.example.test;\n"
        "        location /v1/ {\n"
        "            limit_req zone=api_per_ip burst=10;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_rate_limit_policy(
        tmp_path,
        rate_limits_policy_payload(
            profiles=[
                public_api_rate_limit_profile(
                    request={
                        "required": True,
                        "accepted_zones": ["api_per_ip"],
                        "require_all_zones": False,
                        "additional_zones": "allow",
                        "burst": {"min": 0, "max": 20},
                        "delay_mode": "default",
                        "dry_run": False,
                        "allowed_rejection_statuses": [429],
                        "allowed_log_levels": ["notice"],
                    },
                    connection={"required": False},
                )
            ],
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    request = _assessment(
        result,
        "cis-nginx-5.2.5.requests-per-ip",
        profile_id="public-api",
    )
    assert request.status == "fail"


def test_rate_limit_policy_rejects_additional_request_zones_not_declared_in_inventory(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=api_per_ip:10m rate=5r/s;\n"
        "    limit_req_zone $binary_remote_addr zone=burst_per_ip:10m rate=10r/s;\n"
        "    server {\n"
        "        server_name api.example.test;\n"
        "        location /v1/ {\n"
        "            limit_req zone=api_per_ip burst=10;\n"
        "            limit_req zone=burst_per_ip burst=20;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_rate_limit_policy(
        tmp_path,
        rate_limits_policy_payload(
            profiles=[
                public_api_rate_limit_profile(
                    request={
                        "required": True,
                        "accepted_zones": ["api_per_ip"],
                        "require_all_zones": False,
                        "additional_zones": "require_in_inventory",
                        "burst": {"min": 0, "max": 20},
                        "delay_mode": "default",
                        "dry_run": False,
                        "allowed_rejection_statuses": [429, 503],
                        "allowed_log_levels": ["notice", "warn", "error"],
                    },
                    connection={"required": False},
                )
            ],
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    request = _assessment(
        result,
        "cis-nginx-5.2.5.requests-per-ip",
        profile_id="public-api",
    )
    assert request.status == "fail"
    assert "unapproved-additional-request-zone" in request.metadata["failures"]


def test_rate_limit_policy_suppresses_review_findings_only_when_explicit_policy_applies(
    tmp_path: Path,
) -> None:
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
    policy = resolved_rate_limit_policy(
        tmp_path,
        rate_limits_policy_payload(
            profiles=[public_api_rate_limit_profile()],
            requested_opt_in_tags=("policy-review",),
        ),
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=policy,
        enable_policy_review=True,
    )

    assert "nginx.limit_req_zone_rate_review" not in {
        finding.rule_id for finding in result.findings
    }
    assert "nginx.limit_conn_zone_review" not in {
        finding.rule_id for finding in result.findings
    }
