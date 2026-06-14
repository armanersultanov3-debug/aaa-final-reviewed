from __future__ import annotations

from pathlib import Path

import yaml

from webconf_audit.audit_policy import AuditTarget, load_audit_policy, resolve_audit_policy
from webconf_audit.coverage_ledger import load_coverage_ledger


def base_policy_payload(
    *,
    requested_opt_in_tags: tuple[str, ...] = (),
) -> dict[str, object]:
    target_profile: dict[str, object] = {
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
    if requested_opt_in_tags:
        target_profile["requested_opt_in_tags"] = list(requested_opt_in_tags)
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
        "profiles": [target_profile],
        "provenance": {
            "owner": "Security Engineering",
            "approved_on": "2026-06-12",
            "change_ref": "SEC-2026-206",
        },
    }


def server_logging_profile() -> dict[str, object]:
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


def logging_policy_payload(
    *,
    logging_profiles: list[dict[str, object]],
    requested_opt_in_tags: tuple[str, ...] = (),
) -> dict[str, object]:
    payload = base_policy_payload(requested_opt_in_tags=requested_opt_in_tags)
    payload["nginx"] = {
        "logging": {
            "profiles": logging_profiles,
            "unmatched_scopes": "indeterminate",
        }
    }
    return payload


def write_policy(tmp_path: Path, payload: dict[str, object]) -> Path:
    policy_path = tmp_path / ".webconf-audit-policy.yml"
    policy_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return policy_path


def resolved_policy(
    tmp_path: Path,
    payload: dict[str, object],
    *,
    target_name: str = "nginx.conf",
):
    ledger = load_coverage_ledger()
    policy = load_audit_policy(write_policy(tmp_path, payload))
    return resolve_audit_policy(
        policy,
        AuditTarget(
            mode="local",
            server_type="nginx",
            target=str(tmp_path / target_name),
        ),
        ledger,
    )
