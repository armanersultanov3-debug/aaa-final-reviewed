from __future__ import annotations

from pathlib import Path

import yaml

from webconf_audit.external.tls_inventory import (
    TLSInventoryEntryAnalysis,
    TLSInventoryEntryResult,
    TLSObservation,
    analyze_external_tls_inventory,
)
from webconf_audit.models import Finding, SourceLocation


def _policy_payload(*, declared_complete: bool = True) -> dict[str, object]:
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
                "profile_id": "tls-inventory",
                "title": "TLS inventory",
                "selectors": [
                    {
                        "mode": "external",
                        "target_glob": "tls-inventory/*",
                    }
                ],
                "sources": [
                    {
                        "source_id": "cis-nginx-3.0.0",
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
                    "declared_complete": declared_complete,
                    "completeness_attestation": (
                        {
                            "asserted_by": "platform-team",
                            "asserted_at": "2026-06-12T08:00:00Z",
                            "basis": "load-balancer-listener-export",
                        }
                        if declared_complete
                        else None
                    ),
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
                            "http_host": "api.example.test",
                            "path": "/",
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


def _set_required_evidence(
    payload: dict[str, object],
    requirements: list[str],
) -> None:
    external = payload["external"]
    assert isinstance(external, dict)
    inventories = external["tls_inventories"]
    assert isinstance(inventories, list)
    inventory = inventories[0]
    assert isinstance(inventory, dict)
    inventory["required_evidence"] = requirements


def _write_policy(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "audit-policy.yml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _observed_analysis(inventory_id: str, entry_id: str) -> TLSInventoryEntryAnalysis:
    observations = tuple(
        TLSObservation(
            requirement=requirement,
            state="observed",
            reason=f"{requirement} observed.",
            evidence_refs=(f"tls_inventory.{entry_id}.{requirement}",),
        )
        for requirement in (
            "handshake",
            "certificate_name",
            "certificate_chain",
            "protocol_support",
            "negotiated_cipher",
            "ocsp_stapling",
        )
    )
    return TLSInventoryEntryAnalysis(
        result=TLSInventoryEntryResult(
            inventory_id=inventory_id,
            entry_id=entry_id,
            identity={
                "connect_host": "203.0.113.10",
                "connect_port": 443,
                "sni_name": "api.example.test",
                "http_host": "api.example.test",
            },
            probe_url="https://api.example.test/",
            observations=observations,
        )
    )


def test_tls_inventory_analysis_records_identity_and_pass_assessment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fake_probe(entry, inventory, **_kwargs):
        return _observed_analysis(inventory.inventory_id, entry.entry_id)

    monkeypatch.setattr(
        "webconf_audit.external.tls_inventory._probe_inventory_entry",
        fake_probe,
    )
    result = analyze_external_tls_inventory(
        _write_policy(tmp_path, _policy_payload()),
        "production-edge",
    )

    assert result.target == "tls-inventory/production-edge"
    inventory = result.metadata["tls_inventory"]
    assert inventory["inventory_id"] == "production-edge"
    assert inventory["declared_complete"] is True
    assert inventory["observation_complete"] is True
    assert inventory["entries"][0]["identity"]["sni_name"] == "api.example.test"
    assert {
        observation["state"]
        for observation in inventory["entries"][0]["observations"]
    } == {"observed"}
    assert result.control_assessments[0].status == "pass"
    assert result.findings == []


def test_tls_inventory_incomplete_declaration_is_indeterminate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fake_probe(entry, inventory, **_kwargs):
        return _observed_analysis(inventory.inventory_id, entry.entry_id)

    monkeypatch.setattr(
        "webconf_audit.external.tls_inventory._probe_inventory_entry",
        fake_probe,
    )

    result = analyze_external_tls_inventory(
        _write_policy(tmp_path, _policy_payload(declared_complete=False)),
        "production-edge",
    )

    assert result.metadata["tls_inventory"]["declared_complete"] is False
    assert result.control_assessments[0].status == "indeterminate"
    assert "inventory completeness was not declared" in result.control_assessments[0].summary


def test_tls_inventory_failed_mandatory_observation_is_indeterminate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fake_probe(entry, inventory, **_kwargs):
        analysis = _observed_analysis(inventory.inventory_id, entry.entry_id)
        observations = tuple(
            observation.model_copy(
                update={
                    "state": "failed",
                    "reason": "TLS alert during chain probe.",
                }
            )
            if observation.requirement == "certificate_chain"
            else observation
            for observation in analysis.result.observations
        )
        return TLSInventoryEntryAnalysis(
            result=analysis.result.model_copy(update={"observations": observations})
        )

    monkeypatch.setattr(
        "webconf_audit.external.tls_inventory._probe_inventory_entry",
        fake_probe,
    )

    result = analyze_external_tls_inventory(
        _write_policy(tmp_path, _policy_payload()),
        "production-edge",
    )

    assert result.metadata["tls_inventory"]["observation_complete"] is False
    assert result.control_assessments[0].status == "indeterminate"
    assert "api-primary:certificate_chain" in result.control_assessments[0].metadata[
        "missing_evidence"
    ]


def test_tls_inventory_scopes_findings_to_inventory_entry(
    tmp_path: Path,
    monkeypatch,
) -> None:
    finding = Finding(
        rule_id="external.cert_chain_incomplete",
        title="Certificate chain verification failed",
        severity="medium",
        description="Certificate chain verification failed.",
        recommendation="Fix the certificate chain.",
        location=SourceLocation(
            mode="external",
            kind="tls",
            target="https://api.example.test/",
            details="verify_error: self signed",
        ),
    )

    def fake_probe(entry, inventory, **_kwargs):
        return TLSInventoryEntryAnalysis(
            result=_observed_analysis(inventory.inventory_id, entry.entry_id).result,
            findings=(finding,),
        )

    monkeypatch.setattr(
        "webconf_audit.external.tls_inventory._probe_inventory_entry",
        fake_probe,
    )

    result = analyze_external_tls_inventory(
        _write_policy(tmp_path, _policy_payload()),
        "production-edge",
    )

    assert result.control_assessments[0].status == "fail"
    assert result.findings[0].metadata["scope_id"] == "tls-inventory:production-edge:api-primary"
    assert result.findings[0].metadata["tls_inventory_identity"]["connect_host"] == "203.0.113.10"
    assert result.metadata["tls_inventory"]["entries"][0]["finding_fingerprints"]


def test_tls_inventory_optional_tls_finding_does_not_block_pass(
    tmp_path: Path,
    monkeypatch,
) -> None:
    finding = Finding(
        rule_id="external.ocsp_stapling_not_observed",
        title="OCSP stapling not observed",
        severity="low",
        description="OCSP stapling was not observed during the bounded TLS probe.",
        recommendation="Enable OCSP stapling.",
        location=SourceLocation(
            mode="external",
            kind="tls",
            target="https://api.example.test/",
            details="stapled: false",
        ),
    )

    def fake_probe(entry, inventory, **_kwargs):
        return TLSInventoryEntryAnalysis(
            result=_observed_analysis(inventory.inventory_id, entry.entry_id).result,
            findings=(finding,),
        )

    monkeypatch.setattr(
        "webconf_audit.external.tls_inventory._probe_inventory_entry",
        fake_probe,
    )

    payload = _policy_payload()
    _set_required_evidence(payload, ["handshake"])
    result = analyze_external_tls_inventory(
        _write_policy(tmp_path, payload),
        "production-edge",
    )

    assert result.control_assessments[0].status == "pass"
    assert result.findings[0].rule_id == "external.ocsp_stapling_not_observed"
    assert any(
        "Optional TLS evidence produced a finding" in limitation
        for limitation in result.control_assessments[0].metadata["limitations"]
    )


def test_tls_inventory_unknown_id_returns_analysis_issue(tmp_path: Path) -> None:
    result = analyze_external_tls_inventory(
        _write_policy(tmp_path, _policy_payload()),
        "missing",
    )

    assert result.issues[0].code == "tls_inventory_not_found"
    assert result.target == "tls-inventory/missing"
