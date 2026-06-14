from __future__ import annotations

from pathlib import Path

import pytest

from tests.nginx_rate_limit_policy_helpers import (
    public_api_rate_limit_profile,
    rate_limits_policy_payload,
)
from tests.nginx_sensitive_location_policy_helpers import write_policy
from webconf_audit.coverage_ledger import load_coverage_ledger


def _load_registry():
    from webconf_audit.cli import _ensure_all_rules_loaded
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    return registry


def test_load_validate_and_resolve_policy_with_nginx_rate_limits(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import (
        AuditTarget,
        load_audit_policy,
        resolve_audit_policy,
        validate_audit_policy,
    )

    payload = rate_limits_policy_payload(
        profiles=[public_api_rate_limit_profile()],
    )
    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(write_policy(tmp_path, payload))

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
    assert resolved.nginx.rate_limits is not None
    profile = resolved.nginx.rate_limits.profiles[0]
    assert profile.profile_id == "public-api"
    assert profile.request is not None
    assert profile.connection is not None
    assert profile.request.accepted_zones == ("api_per_ip",)


def test_policy_payload_preserves_explicitly_empty_rate_limit_inventories(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy

    payload = rate_limits_policy_payload(
        profiles=[
            public_api_rate_limit_profile(
                request={"required": False},
                connection={"required": False},
            )
        ],
        request_inventory={},
        connection_inventory={},
    )
    policy = load_audit_policy(write_policy(tmp_path, payload))

    assert policy.nginx is not None
    assert policy.nginx.rate_limits is not None
    assert policy.nginx.rate_limits.zone_inventory.request == {}
    assert policy.nginx.rate_limits.zone_inventory.connection == {}


def test_validate_policy_rejects_overlapping_nginx_rate_limit_profiles(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    payload = rate_limits_policy_payload(
        profiles=[
            public_api_rate_limit_profile(profile_id="api-a"),
            public_api_rate_limit_profile(
                profile_id="api-b",
                request={
                    "required": True,
                    "accepted_zones": ["api_per_ip"],
                    "require_all_zones": False,
                    "additional_zones": "allow",
                    "burst": {"min": 0, "max": 5},
                    "delay_mode": "default",
                    "dry_run": False,
                    "allowed_rejection_statuses": [429],
                    "allowed_log_levels": ["notice", "warn", "error"],
                },
            ),
        ],
    )
    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(write_policy(tmp_path, payload))

    issues = validate_audit_policy(policy, ledger, registry)

    assert [issue.code for issue in issues] == [
        "overlapping_nginx_rate_limit_profiles"
    ]


def test_validate_policy_rejects_unknown_rate_limit_inventory_reference(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    payload = rate_limits_policy_payload(
        profiles=[
            public_api_rate_limit_profile(
                request={
                    "required": True,
                    "accepted_zones": ["missing_req_zone"],
                    "require_all_zones": False,
                    "additional_zones": "allow",
                    "burst": {"min": 0, "max": 20},
                    "delay_mode": "default",
                    "dry_run": False,
                    "allowed_rejection_statuses": [429],
                    "allowed_log_levels": ["notice", "warn", "error"],
                }
            )
        ],
    )
    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(write_policy(tmp_path, payload))

    issues = validate_audit_policy(policy, ledger, registry)

    assert [issue.code for issue in issues] == [
        "unknown_nginx_rate_limit_request_zone_reference"
    ]


def test_load_policy_rejects_delay_mode_with_delayed_requests_for_nodelay(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    payload = rate_limits_policy_payload(
        profiles=[
            public_api_rate_limit_profile(
                request={
                    "required": True,
                    "accepted_zones": ["api_per_ip"],
                    "require_all_zones": False,
                    "additional_zones": "allow",
                    "burst": {"min": 0, "max": 20},
                    "delay_mode": "nodelay",
                    "delayed_requests": {"min": 1, "max": 10},
                    "dry_run": False,
                    "allowed_rejection_statuses": [429],
                    "allowed_log_levels": ["notice", "warn", "error"],
                }
            )
        ],
    )

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(write_policy(tmp_path, payload))

    assert excinfo.value.issue.code == "policy_schema_invalid"
