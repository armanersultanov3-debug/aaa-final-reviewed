from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from webconf_audit.cli import _ensure_all_rules_loaded
from webconf_audit.coverage_ledger import load_coverage_ledger


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


def _logging_profile() -> dict[str, object]:
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
                    {"kind": "syslog", "prefix": "syslog:server=logs.example.test"},
                ],
                "require_at_least_one_remote": False,
                "allow_variable_paths": False,
            },
            "formats": {
                "allowed_names": ["main_json"],
                "require_escape": "json",
                "required_field_groups": {
                    "timestamp": ["$time_iso8601"],
                    "client_ip": ["$remote_addr", "$realip_remote_addr"],
                    "request": ["$request"],
                    "status": ["$status"],
                    "correlation": ["$request_id", "$http_x_request_id"],
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


def _logging_policy_payload() -> dict[str, object]:
    payload = _base_policy_payload()
    payload["nginx"] = {
        "logging": {
            "profiles": [_logging_profile()],
            "unmatched_scopes": "indeterminate",
        }
    }
    return payload


def _write_policy(tmp_path: Path, payload: dict[str, object]) -> Path:
    policy_path = tmp_path / ".webconf-audit-policy.yml"
    policy_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return policy_path


def _load_registry():
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    return registry


def test_load_validate_and_resolve_policy_with_nginx_logging(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditTarget, load_audit_policy, resolve_audit_policy, validate_audit_policy

    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(_write_policy(tmp_path, _logging_policy_payload()))

    assert validate_audit_policy(policy, ledger, registry) == ()

    resolved = resolve_audit_policy(
        policy,
        AuditTarget(
            mode="local",
            server_type="nginx",
            target=str(tmp_path / "nginx.conf"),
        ),
        ledger,
    )

    assert resolved.nginx is not None
    assert resolved.nginx.logging is not None
    profile = resolved.nginx.logging.profiles[0]
    assert profile.profile_id == "public-server"
    assert profile.access is not None
    assert profile.error is not None


def test_validate_policy_rejects_overlapping_nginx_logging_profiles(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    payload = _logging_policy_payload()
    payload["nginx"]["logging"]["profiles"].append(  # type: ignore[index]
        {
            "profile_id": "public-server-alt",
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
                        {"kind": "file", "path": "/srv/log/nginx/access.log"},
                    ],
                    "require_at_least_one_remote": False,
                    "allow_variable_paths": False,
                },
                "formats": {
                    "allowed_names": ["main_json"],
                    "require_escape": "json",
                    "required_field_groups": {
                        "timestamp": ["$time_iso8601"],
                    },
                    "forbidden_variables": [],
                },
            },
        }
    )

    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(_write_policy(tmp_path, payload))
    issues = validate_audit_policy(policy, ledger, registry)

    assert [issue.code for issue in issues] == ["overlapping_nginx_logging_profiles"]


def test_load_policy_rejects_forbidden_variable_inside_required_group(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    payload = _logging_policy_payload()
    payload["nginx"]["logging"]["profiles"][0]["access"]["formats"]["required_field_groups"][  # type: ignore[index]
        "credentials"
    ] = ["$http_authorization"]

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(_write_policy(tmp_path, payload))

    assert excinfo.value.issue.code == "policy_schema_invalid"
