from __future__ import annotations

from pathlib import Path

from tests.nginx_logging_policy_helpers import (
    logging_policy_payload,
    resolved_policy,
    server_logging_profile,
)
from webconf_audit.local.nginx import analyze_nginx_config


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
    assert len(matches) == 1, control_id
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
        policy=resolved_policy(
            tmp_path,
            logging_policy_payload(logging_profiles=[server_logging_profile()]),
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
    profile = server_logging_profile()
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
        policy=resolved_policy(
            tmp_path,
            logging_policy_payload(logging_profiles=[profile]),
        ),
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
    profile = server_logging_profile()
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
        policy=resolved_policy(
            tmp_path,
            logging_policy_payload(logging_profiles=[profile]),
        ),
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
    profile = server_logging_profile()
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
        policy=resolved_policy(
            tmp_path,
            logging_policy_payload(logging_profiles=[profile]),
        ),
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
        policy=resolved_policy(
            tmp_path,
            logging_policy_payload(logging_profiles=[server_logging_profile()]),
        ),
    )

    access = _assessment(result, "cis-nginx-3.1.detailed-access-logging")

    assert access.status == "indeterminate"
    assert "nginx.missing_log_format" in {finding.rule_id for finding in result.findings}


def test_logging_policy_marks_only_incomplete_server_branch_indeterminate(
    tmp_path: Path,
) -> None:
    profile = server_logging_profile()
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
        policy=resolved_policy(
            tmp_path,
            logging_policy_payload(logging_profiles=[profile]),
        ),
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
    assert status_by_server[("broken.test", "error")] == "indeterminate"
    assert status_by_server[("healthy.test", "error")] == "pass"


def test_logging_policy_suppresses_default_format_review_when_explicit_policy_applies(
    tmp_path: Path,
) -> None:
    profile = server_logging_profile()
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
        policy=resolved_policy(
            tmp_path,
            logging_policy_payload(
                logging_profiles=[profile],
                requested_opt_in_tags=("policy-review",),
            ),
        ),
    )

    assert "nginx.access_log_uses_default_format" not in {
        finding.rule_id for finding in result.findings
    }
    assert _assessment(result, "cis-nginx-3.1.detailed-access-logging").status == "pass"


def test_logging_policy_does_not_suppress_default_format_review_without_format_evaluation(
    tmp_path: Path,
) -> None:
    profile = server_logging_profile()
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
        "        access_log /var/log/nginx/access.log if=0;\n"
        "        error_log /var/log/nginx/error.log info;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(
        str(config_path),
        policy=resolved_policy(
            tmp_path,
            logging_policy_payload(
                logging_profiles=[profile],
                requested_opt_in_tags=("policy-review",),
            ),
        ),
    )

    assert "nginx.access_log_uses_default_format" in {
        finding.rule_id for finding in result.findings
    }
    assert _assessment(result, "cis-nginx-3.1.detailed-access-logging").status == "fail"


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
        policy=resolved_policy(
            tmp_path,
            logging_policy_payload(logging_profiles=[server_logging_profile()]),
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
        policy=resolved_policy(
            tmp_path,
            logging_policy_payload(logging_profiles=[server_logging_profile()]),
        ),
    )

    assert _assessment(result, "cis-nginx-3.1.detailed-access-logging").status == "fail"
