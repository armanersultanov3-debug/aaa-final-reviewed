from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from webconf_audit.cli import app
from webconf_audit.models import AnalysisResult

runner = CliRunner()


def _policy_path(tmp_path: Path) -> Path:
    payload = {
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
                    {"mode": "external", "target_glob": "tls-inventory/*"}
                ],
                "sources": [{"source_id": "cis-nginx-3.0.0", "disposition": "required"}],
            }
        ],
        "external": {
            "tls_inventories": [
                {
                    "id": "production-edge",
                    "declared_complete": False,
                    "trust": {"mode": "system"},
                    "required_evidence": ["handshake"],
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
    path = tmp_path / "audit-policy.yml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_analyze_tls_inventory_cli_requires_policy(tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze-tls-inventory", "production-edge"])

    assert result.exit_code != 0
    assert "--policy" in result.output


def test_analyze_tls_inventory_cli_uses_existing_output_options(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fake_analyze(policy, inventory_id):
        assert str(policy).endswith("audit-policy.yml")
        assert inventory_id == "production-edge"
        return AnalysisResult(
            mode="external",
            target="tls-inventory/production-edge",
            metadata={
                "tls_inventory": {
                    "inventory_id": "production-edge",
                    "declared_complete": False,
                    "observation_complete": False,
                    "entries": [],
                }
            },
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_external_tls_inventory", fake_analyze)

    result = runner.invoke(
        app,
        [
            "analyze-tls-inventory",
            "production-edge",
            "--policy",
            str(_policy_path(tmp_path)),
            "--format",
            "json",
            "--group-by-cause",
        ],
    )

    assert result.exit_code == 0, result.output
    assert '"target": "tls-inventory/production-edge"' in result.stdout
    assert '"tls_inventory"' in result.stdout


def test_analyze_tls_inventory_cli_returns_exit_1_for_unknown_inventory(
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "analyze-tls-inventory",
            "missing",
            "--policy",
            str(_policy_path(tmp_path)),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    assert '"code": "tls_inventory_not_found"' in result.stdout
