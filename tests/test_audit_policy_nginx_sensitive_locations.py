from __future__ import annotations

from pathlib import Path

import pytest

from tests.nginx_sensitive_location_policy_helpers import (
    sensitive_location_entry,
    sensitive_locations_policy_payload,
    write_policy,
)
from webconf_audit.coverage_ledger import load_coverage_ledger


def _load_registry():
    from webconf_audit.cli import _ensure_all_rules_loaded
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    return registry


def test_load_validate_and_resolve_policy_with_sensitive_locations(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditTarget, load_audit_policy, resolve_audit_policy, validate_audit_policy

    payload = sensitive_locations_policy_payload(
        catalog=[sensitive_location_entry()],
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
    assert resolved.nginx.sensitive_locations is not None
    entry = resolved.nginx.sensitive_locations.catalog[0]
    assert entry.entry_id == "admin-console"
    assert entry.declared_location is not None
    assert entry.declared_location.modifier == "prefix_no_regex"
    assert entry.sample_uris == ("/admin/",)


def test_load_policy_rejects_invalid_sensitive_location_sample_uri(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    payload = sensitive_locations_policy_payload(
        catalog=[
            sensitive_location_entry(
                sample_uris=("https://example.test/admin",),
            )
        ],
    )

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(write_policy(tmp_path, payload))

    assert excinfo.value.issue.code == "policy_schema_invalid"


def test_load_policy_rejects_disabled_exposure_without_deny_all_requirement(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    payload = sensitive_locations_policy_payload(
        catalog=[
            sensitive_location_entry(
                entry_id="openapi",
                kind="documentation",
                sample_uris=("/openapi.json",),
                exposure="disabled",
                required_controls={"auth_request": {}},
            )
        ],
    )

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(write_policy(tmp_path, payload))

    assert excinfo.value.issue.code == "policy_schema_invalid"


def test_validate_policy_rejects_overlapping_sensitive_location_entries(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    payload = sensitive_locations_policy_payload(
        catalog=[
            sensitive_location_entry(entry_id="admin-a"),
            sensitive_location_entry(
                entry_id="admin-b",
                required_controls={"auth_basic": {}},
            ),
        ],
    )
    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(write_policy(tmp_path, payload))

    issues = validate_audit_policy(policy, ledger, registry)

    assert [issue.code for issue in issues] == [
        "overlapping_nginx_sensitive_location_entries"
    ]


def test_validate_policy_accepts_equivalent_ip_and_single_host_allowlist_aliases(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    payload = sensitive_locations_policy_payload(
        catalog=[
            sensitive_location_entry(
                entry_id="admin-a",
                required_controls={
                    "all_of": [
                        {
                            "ip_allowlist": {
                                "allowed_cidrs": ["10.20.0.1"],
                                "require_deny_all_fallback": True,
                            }
                        },
                        {"auth_request": {}},
                    ],
                    "satisfy": "all",
                },
            ),
            sensitive_location_entry(
                entry_id="admin-b",
                required_controls={
                    "all_of": [
                        {
                            "ip_allowlist": {
                                "allowed_cidrs": ["10.20.0.1/32"],
                                "require_deny_all_fallback": True,
                            }
                        },
                        {"auth_request": {}},
                    ],
                    "satisfy": "all",
                },
            ),
        ],
    )
    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(write_policy(tmp_path, payload))

    assert validate_audit_policy(policy, ledger, registry) == ()
