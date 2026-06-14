from __future__ import annotations

from pathlib import Path

import yaml

from webconf_audit.audit_policy import AuditTarget, load_audit_policy, resolve_audit_policy
from webconf_audit.coverage_ledger import load_coverage_ledger
from webconf_audit.local.nginx import analyze_nginx_config


def _base_policy_payload() -> dict[str, object]:
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
        "provenance": {
            "owner": "Security Engineering",
            "approved_on": "2026-06-12",
            "change_ref": "SEC-2026-206",
        },
    }


def _server_logging_profile() -> dict[str, object]:
    return {
        "profile_id": "public-server",
        "applies_to": {
            "server_names": ["example.test"],
        },
        "access": {
            "required": True,
            "allow_off": False,
            "conditional": {
                "mode": "forbid",
                "allowed_conditions": [],
            },
            "destinations": {
                "allowed": [
                    {"kind": "file", "path": "/var/log/nginx/access.log"},
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


def _policy_payload(*, logging_profiles: list[dict[str, object]]) -> dict[str, object]:
    payload = _base_policy_payload()
    payload["nginx"] = {
        "logging": {
            "profiles": logging_profiles,
            "unmatched_scopes": "indeterminate",
        }
    }
    return payload


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


def _assessment(result, control_id: str, *, logging_scope_id: str | None = None):
    matches = [
        entry
        for entry in result.control_assessments
        if entry.control_id == control_id
        and (
            logging_scope_id is None
            or entry.metadata["logging_scope_id"] == logging_scope_id
        )
    ]
    assert matches, control_id
    return matches[0]


def test_logging_policy_emits_access_and_error_assessments_for_server_scope(
    tmp_path: Path,
) -> None:
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

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(
            tmp_path,
            _policy_payload(logging_profiles=[_server_logging_profile()]),
        ),
    )

    access = _assessment(result, "cis-nginx-3.1.detailed-access-logging")
    error = _assessment(result, "cis-nginx-3.3.error-log-info-level")

    assert access.status == "pass"
    assert access.metadata["policy_section"] == "nginx.logging"
    assert access.metadata["logging_kind"] == "access"
    assert access.metadata["profile_id"] == "public-server"

    assert error.status == "pass"
    assert error.metadata["logging_kind"] == "error"
    assert error.metadata["effective_destinations"][0]["threshold"] == "info"


def test_logging_policy_fails_location_scope_with_access_log_off_even_when_server_logs(
    tmp_path: Path,
) -> None:
    profile = _server_logging_profile()
    profile["profile_id"] = "healthz-location"
    profile["applies_to"] = {
        "server_names": ["example.test"],
        "location_patterns": ["/healthz"],
    }

    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        '    log_format main_json escape=json "$time_iso8601 $remote_addr $request $status $request_id $http_user_agent";\n'
        "    server {\n"
        "        server_name example.test;\n"
        "        access_log /var/log/nginx/access.log main_json;\n"
        "        error_log /var/log/nginx/error.log info;\n"
        "        location /healthz {\n"
        "            access_log off;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(tmp_path, _policy_payload(logging_profiles=[profile])),
    )

    location_assessment = next(
        entry
        for entry in result.control_assessments
        if entry.control_id == "cis-nginx-3.1.detailed-access-logging"
        and entry.metadata["logging_kind"] == "access"
        and entry.scope.route_selector == "/healthz"
    )

    assert location_assessment.status == "fail"
    assert location_assessment.metadata["effective_destinations"] == []


def test_logging_policy_handles_dynamic_conditions_without_guessing_pass(
    tmp_path: Path,
) -> None:
    profile = _server_logging_profile()
    profile["applies_to"] = {
        "server_names": ["example.test"],
        "location_patterns": ["/api/"],
    }
    profile["access"]["conditional"]["mode"] = "allow_dynamic"  # type: ignore[index]

    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        '    log_format main_json escape=json "$time_iso8601 $remote_addr $request $status $request_id $http_user_agent";\n'
        "    server {\n"
        "        server_name example.test;\n"
        "        error_log /var/log/nginx/error.log info;\n"
        "        location /api/ {\n"
        "            access_log /var/log/nginx/access.log main_json if=$loggable;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(tmp_path, _policy_payload(logging_profiles=[profile])),
    )

    access = next(
        entry
        for entry in result.control_assessments
        if entry.control_id == "cis-nginx-3.1.detailed-access-logging"
        and entry.scope.route_selector == "/api/"
    )

    assert access.status == "indeterminate"
    assert any(
        evidence.kind == "route" and evidence.status == "runtime-dependent"
        for evidence in access.evidence
    )


def test_logging_policy_fails_forbidden_dynamic_condition(
    tmp_path: Path,
) -> None:
    profile = _server_logging_profile()
    profile["applies_to"] = {
        "server_names": ["example.test"],
        "location_patterns": ["/api/"],
    }

    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        '    log_format main_json escape=json "$time_iso8601 $remote_addr $request $status $request_id $http_user_agent";\n'
        "    server {\n"
        "        server_name example.test;\n"
        "        error_log /var/log/nginx/error.log info;\n"
        "        location /api/ {\n"
        "            access_log /var/log/nginx/access.log main_json if=$loggable;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(tmp_path, _policy_payload(logging_profiles=[profile])),
    )

    access = next(
        entry
        for entry in result.control_assessments
        if entry.control_id == "cis-nginx-3.1.detailed-access-logging"
        and entry.scope.route_selector == "/api/"
    )

    assert access.status == "fail"


def test_logging_policy_preserves_missing_log_format_finding_and_marks_assessment_indeterminate(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        access_log /var/log/nginx/access.log missing_json;\n"
        "        error_log /var/log/nginx/error.log info;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(
            tmp_path,
            _policy_payload(logging_profiles=[_server_logging_profile()]),
        ),
    )

    access = _assessment(result, "cis-nginx-3.1.detailed-access-logging")

    assert access.status == "indeterminate"
    assert "nginx.missing_log_format" in {finding.rule_id for finding in result.findings}


def test_logging_policy_marks_only_incomplete_server_branch_indeterminate(
    tmp_path: Path,
) -> None:
    profile = _server_logging_profile()
    profile["applies_to"] = {
        "server_names": ["broken.test", "healthy.test"],
    }

    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        '    log_format main_json escape=json "$time_iso8601 $remote_addr $request $status $request_id $http_user_agent";\n'
        "    server {\n"
        "        server_name broken.test;\n"
        "        include missing.conf;\n"
        "        access_log /var/log/nginx/access.log main_json;\n"
        "        error_log /var/log/nginx/error.log info;\n"
        "    }\n"
        "    server {\n"
        "        server_name healthy.test;\n"
        "        access_log /var/log/nginx/access.log main_json;\n"
        "        error_log /var/log/nginx/error.log info;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(tmp_path, _policy_payload(logging_profiles=[profile])),
    )

    status_by_server = {
        (entry.scope.server_name, entry.metadata["logging_kind"]): entry.status
        for entry in result.control_assessments
        if entry.control_id in {
            "cis-nginx-3.1.detailed-access-logging",
            "cis-nginx-3.3.error-log-info-level",
        }
    }

    assert status_by_server[("broken.test", "access")] == "indeterminate"
    assert status_by_server[("healthy.test", "access")] == "pass"


def test_logging_policy_suppresses_default_format_review_when_explicit_policy_applies(
    tmp_path: Path,
) -> None:
    profile = _server_logging_profile()
    profile["access"]["formats"] = {  # type: ignore[index]
        "allowed_names": ["combined"],
        "require_escape": "default",
        "required_field_groups": {
            "timestamp": ["$time_local"],
            "client_ip": ["$remote_addr"],
            "identity": ["$remote_user"],
            "request": ["$request"],
            "status": ["$status"],
            "user_agent": ["$http_user_agent"],
        },
        "forbidden_variables": [],
    }

    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        access_log /var/log/nginx/access.log;\n"
        "        error_log /var/log/nginx/error.log info;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(tmp_path, _policy_payload(logging_profiles=[profile])),
    )

    assert "nginx.access_log_uses_default_format" not in {
        finding.rule_id for finding in result.findings
    }
    assert _assessment(result, "cis-nginx-3.1.detailed-access-logging").status == "pass"


def test_logging_policy_fails_too_restrictive_error_log_threshold(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        '    log_format main_json escape=json "$time_iso8601 $remote_addr $request $status $request_id $http_user_agent";\n'
        "    server {\n"
        "        server_name example.test;\n"
        "        access_log /var/log/nginx/access.log main_json;\n"
        "        error_log /var/log/nginx/error.log notice;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(
            tmp_path,
            _policy_payload(logging_profiles=[_server_logging_profile()]),
        ),
    )

    assert _assessment(result, "cis-nginx-3.3.error-log-info-level").status == "fail"


def test_logging_policy_fails_variable_access_log_path_when_forbidden(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        '    log_format main_json escape=json "$time_iso8601 $remote_addr $request $status $request_id $http_user_agent";\n'
        "    server {\n"
        "        server_name example.test;\n"
        "        access_log $dynamic_log_path main_json;\n"
        "        error_log /var/log/nginx/error.log info;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=_resolved_policy(
            tmp_path,
            _policy_payload(logging_profiles=[_server_logging_profile()]),
        ),
    )

    assert _assessment(result, "cis-nginx-3.1.detailed-access-logging").status == "fail"
