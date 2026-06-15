from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from webconf_audit.coverage_ledger import load_coverage_ledger


def _policy_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "tls-inventory-policy",
        "policy_version": "2026.06",
        "title": "TLS inventory policy",
        "description": "Declared TLS identities for external assessment.",
        "defaults": {
            "disposition": "advisory",
            "evidence_expectation": "ledger-default",
            "include_unmapped_findings": True,
            "require_complete_execution_manifest": True,
        },
        "profiles": [
            {
                "profile_id": "external-tls",
                "title": "External TLS",
                "selectors": [
                    {
                        "mode": "external",
                        "target_glob": "edge.example.test",
                    }
                ],
                "sources": [
                    {
                        "source_id": "owasp-asvs-5.0.0",
                        "disposition": "required",
                    }
                ],
            }
        ],
        "external": {
            "tls_inventories": [
                {
                    "id": "production-edge",
                    "environment": "production",
                    "declared_complete": True,
                    "completeness_attestation": {
                        "asserted_by": "platform-team",
                        "asserted_at": "2026-06-12T08:00:00Z",
                        "basis": "load-balancer-listener-export",
                    },
                    "trust": {"mode": "system"},
                    "required_evidence": [
                        "handshake",
                        "certificate_name",
                        "certificate_chain",
                        "protocol_support",
                        "negotiated_cipher",
                        "ocsp_stapling",
                    ],
                    "entries": [
                        {
                            "id": "api-primary",
                            "connect_host": "203.0.113.10",
                            "connect_port": 443,
                            "sni_name": "api.example.test",
                            "expected_certificate_names": ["api.example.test"],
                        }
                    ],
                }
            ]
        },
        "provenance": {
            "owner": "Security Engineering",
            "approved_on": "2026-06-12",
            "change_ref": "SEC-2026-110",
        },
    }


def _write_policy(
    tmp_path: Path,
    payload: dict[str, object],
    *,
    name: str = "audit-policy.yml",
) -> Path:
    policy_path = tmp_path / name
    policy_path.write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )
    return policy_path


def _load_registry():
    from webconf_audit.cli import _ensure_all_rules_loaded
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    return registry


def _first_inventory(payload: dict[str, object]) -> dict[str, object]:
    external = payload["external"]
    assert isinstance(external, dict)
    inventories = external["tls_inventories"]
    assert isinstance(inventories, list)
    inventory = inventories[0]
    assert isinstance(inventory, dict)
    return inventory


def _first_entry(payload: dict[str, object]) -> dict[str, object]:
    inventory = _first_inventory(payload)
    entries = inventory["entries"]
    assert isinstance(entries, list)
    entry = entries[0]
    assert isinstance(entry, dict)
    return entry


def test_tls_inventory_loads_normalizes_and_exposes_id_aliases(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy

    payload = _policy_payload()
    entry = _first_entry(payload)
    entry["connect_host"] = "2001:0DB8:0:0:0:0:0:1"
    entry["sni_name"] = "T\u00c4ST.Example."
    entry.pop("expected_certificate_names")
    entry["expected_certificate_names"] = ["T\u00c4ST.Example."]

    policy = load_audit_policy(_write_policy(tmp_path, payload))

    assert policy.external is not None
    inventory = policy.external.tls_inventories[0]
    normalized_entry = inventory.entries[0]
    assert inventory.inventory_id == "production-edge"
    assert normalized_entry.entry_id == "api-primary"
    assert normalized_entry.connect_host == "2001:db8::1"
    assert normalized_entry.sni_name == "xn--tst-qla.example"
    assert normalized_entry.http_host == "xn--tst-qla.example"
    assert normalized_entry.path == "/"
    assert normalized_entry.expected_certificate_names == (
        "xn--tst-qla.example",
    )
    assert inventory.model_dump(mode="json", by_alias=True)["id"] == "production-edge"
    assert normalized_entry.model_dump(mode="json", by_alias=True)["id"] == "api-primary"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("connect_port", 0),
        ("connect_port", 65536),
        ("path", "relative"),
        ("path", "/status?verbose=1"),
    ],
)
def test_tls_inventory_rejects_invalid_port_or_path(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    payload = _policy_payload()
    _first_entry(payload)[field] = value

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(_write_policy(tmp_path, payload))

    assert excinfo.value.issue.code == "policy_schema_invalid"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("connect_host", 2130706433),
        ("expected_certificate_names", "localhost"),
    ],
)
def test_tls_inventory_rejects_non_string_identity_values(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    payload = _policy_payload()
    _first_entry(payload)[field] = value

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(_write_policy(tmp_path, payload))

    assert excinfo.value.issue.code == "policy_schema_invalid"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("connect_host", ""),
        ("connect_host", "   "),
        ("sni_name", ""),
        ("sni_name", "   "),
        ("expected_certificate_names", [""]),
        ("expected_certificate_names", ["   "]),
    ],
)
def test_tls_inventory_rejects_empty_or_whitespace_identity_values(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    payload = _policy_payload()
    _first_entry(payload)[field] = value

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(_write_policy(tmp_path, payload))

    assert excinfo.value.issue.code == "policy_schema_invalid"
    assert "identity" in excinfo.value.issue.message.lower()


def test_tls_inventory_rejects_unknown_evidence_and_unknown_keys(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    unknown_evidence = _policy_payload()
    _first_inventory(unknown_evidence)["required_evidence"] = ["handshake", "dns_discovery"]
    with pytest.raises(AuditPolicyLoadError) as evidence_error:
        load_audit_policy(
            _write_policy(tmp_path, unknown_evidence, name="unknown-evidence.yml")
        )
    assert evidence_error.value.issue.code == "policy_schema_invalid"

    unknown_key = _policy_payload()
    _first_entry(unknown_key)["private_key"] = "do-not-accept.pem"
    with pytest.raises(AuditPolicyLoadError) as key_error:
        load_audit_policy(_write_policy(tmp_path, unknown_key, name="unknown-key.yml"))
    assert key_error.value.issue.code == "policy_schema_invalid"


def test_tls_inventory_declared_complete_requires_attestation(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    payload = _policy_payload()
    _first_inventory(payload).pop("completeness_attestation")

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(_write_policy(tmp_path, payload))

    assert excinfo.value.issue.code == "policy_schema_invalid"
    assert "attestation" in excinfo.value.issue.message.lower()


def test_tls_inventory_rejects_duplicate_inventory_and_entry_ids(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    duplicate_inventory = _policy_payload()
    external = duplicate_inventory["external"]
    assert isinstance(external, dict)
    inventories = external["tls_inventories"]
    assert isinstance(inventories, list)
    inventories.append(deepcopy(inventories[0]))
    with pytest.raises(AuditPolicyLoadError):
        load_audit_policy(
            _write_policy(tmp_path, duplicate_inventory, name="duplicate-inventory.yml")
        )

    duplicate_entry = _policy_payload()
    inventory = _first_inventory(duplicate_entry)
    entries = inventory["entries"]
    assert isinstance(entries, list)
    second_entry = deepcopy(entries[0])
    assert isinstance(second_entry, dict)
    second_entry["connect_host"] = "203.0.113.11"
    entries.append(second_entry)
    with pytest.raises(AuditPolicyLoadError):
        load_audit_policy(
            _write_policy(tmp_path, duplicate_entry, name="duplicate-entry.yml")
        )


@pytest.mark.parametrize(
    ("first_host", "second_host"),
    [
        ("EXAMPLE.Test.", "example.test"),
        ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
    ],
)
def test_tls_inventory_rejects_duplicate_normalized_identity_tuples(
    tmp_path: Path,
    first_host: str,
    second_host: str,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    payload = _policy_payload()
    inventory = _first_inventory(payload)
    entries = inventory["entries"]
    assert isinstance(entries, list)
    first_entry = entries[0]
    assert isinstance(first_entry, dict)
    first_entry["connect_host"] = first_host
    second_entry = deepcopy(first_entry)
    assert isinstance(second_entry, dict)
    second_entry["id"] = "api-secondary"
    second_entry["connect_host"] = second_host
    entries.append(second_entry)

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(_write_policy(tmp_path, payload))

    assert excinfo.value.issue.code == "policy_schema_invalid"
    assert "identity" in excinfo.value.issue.message.lower()


def test_tls_inventory_missing_sni_requires_certificate_name_not_applicable(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    missing_declaration = _policy_payload()
    _first_entry(missing_declaration).pop("sni_name")
    with pytest.raises(AuditPolicyLoadError):
        load_audit_policy(
            _write_policy(tmp_path, missing_declaration, name="missing-sni.yml")
        )

    explicit = _policy_payload()
    entry = _first_entry(explicit)
    entry.pop("sni_name")
    entry.pop("expected_certificate_names")
    entry["not_applicable"] = {
        "certificate_name": {
            "reason": "The endpoint is intentionally addressed by IP without SNI.",
        }
    }

    policy = load_audit_policy(_write_policy(tmp_path, explicit, name="explicit-na.yml"))

    assert policy.external is not None
    normalized_entry = policy.external.tls_inventories[0].entries[0]
    assert normalized_entry.sni_name is None
    assert normalized_entry.http_host is None
    assert (
        normalized_entry.not_applicable["certificate_name"].reason
        == "The endpoint is intentionally addressed by IP without SNI."
    )


def test_tls_inventory_custom_trust_path_is_validated_relative_to_policy(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "root-ca.pem").write_text("test-ca", encoding="utf-8")

    payload = _policy_payload()
    _first_inventory(payload)["trust"] = {
        "mode": "custom",
        "ca_path": "trust/root-ca.pem",
    }
    policy = load_audit_policy(_write_policy(tmp_path, payload))

    assert validate_audit_policy(
        policy,
        load_coverage_ledger(),
        _load_registry(),
    ) == ()

    missing_payload = deepcopy(payload)
    _first_inventory(missing_payload)["trust"] = {
        "mode": "custom",
        "ca_path": "trust/missing.pem",
    }
    missing_policy = load_audit_policy(
        _write_policy(tmp_path, missing_payload, name="missing-custom-ca.yml")
    )
    issues = validate_audit_policy(
        missing_policy,
        load_coverage_ledger(),
        _load_registry(),
    )

    assert [issue.code for issue in issues] == ["tls_inventory_custom_ca_unreadable"]
    assert issues[0].item_id == "production-edge"
    assert issues[0].path == str(tmp_path / "trust" / "missing.pem")


def test_tls_inventory_propagates_through_resolution_and_hashes(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import (
        AuditTarget,
        load_audit_policy,
        resolve_audit_policy,
    )

    ledger = load_coverage_ledger()
    payload = _policy_payload()
    policy = load_audit_policy(_write_policy(tmp_path, payload))
    resolved = resolve_audit_policy(
        policy,
        AuditTarget(mode="external", target="edge.example.test"),
        ledger,
    )

    assert resolved.external == policy.external
    assert resolved.resolved_sha256

    changed_payload = deepcopy(payload)
    _first_entry(changed_payload)["connect_port"] = 8443
    changed = resolve_audit_policy(
        load_audit_policy(
            _write_policy(tmp_path, changed_payload, name="changed-policy.yml")
        ),
        AuditTarget(mode="external", target="edge.example.test"),
        ledger,
    )

    assert changed.raw_sha256 != resolved.raw_sha256
    assert changed.resolved_sha256 != resolved.resolved_sha256


def test_policy_without_external_section_remains_compatible(tmp_path: Path) -> None:
    from webconf_audit.audit_policy import (
        AuditTarget,
        load_audit_policy,
        resolve_audit_policy,
    )

    payload = _policy_payload()
    payload.pop("external")
    policy = load_audit_policy(_write_policy(tmp_path, payload))
    resolved = resolve_audit_policy(
        policy,
        AuditTarget(mode="external", target="edge.example.test"),
        load_coverage_ledger(),
    )

    assert policy.external is None
    assert resolved.external is None
    assert "external" not in policy.model_dump(mode="json")
    assert "external" not in resolved.model_dump(mode="json")
