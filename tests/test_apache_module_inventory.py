from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from tests.apache_helpers import _safe_apache_config
from tests.assessment_helpers import (
    analysis_report_payload,
    ensure_rules_loaded,
    manifest_for,
    resolve_policy,
    result_with_context,
    subset_ledger,
    write_payload,
)
from webconf_audit.assessment import build_control_assessment, load_analysis_report
from webconf_audit.coverage_models import AssessableControlEvidence
from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.apache.module_inventory import (
    evaluate_apache_modules,
    load_apache_module_snapshot,
)
from webconf_audit.local.apache.parser import parse_apache_config
from webconf_audit.policy_models import AuditPolicy
from webconf_audit.rule_registry import registry

CONTROL_ID = "apache.module_inventory"
SOURCE_ID = "cis-apache-http-server-2.4-2.3.0"
ITEM_ID = "apache-2.1-module-minimization"
FULL_ITEM_ID = "apache-4.1-os-root-access-denied"


def _write_config(tmp_path: Path, *lines: str) -> Path:
    path = tmp_path / "httpd.conf"
    path.write_text(_safe_apache_config(*lines), encoding="utf-8")
    return path


def _snapshot_payload(
    *,
    completeness: str = "complete",
    modules: list[dict[str, object]] | None = None,
    host: str = "prod-web-01",
    snapshot_id: str = "prod-web-01-20260612",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "apache-module-inventory",
        "snapshot_id": snapshot_id,
        "host": host,
        "captured_at": "2026-06-12T08:00:00Z",
        "apache": {
            "version": "2.4.63",
            "configuration_id": "sha256:demo-config",
        },
        "completeness": {
            "state": completeness,
            "basis": "operator-export-of-effective-loaded-modules",
        },
        "modules": modules
        if modules is not None
        else [
            {
                "name": "authz_core_module",
                "state": "loaded",
                "linkage": "static",
                "source": "runtime-snapshot",
            },
            {
                "name": "ssl_module",
                "state": "loaded",
                "linkage": "shared",
                "source": "runtime-snapshot",
            },
            {
                "name": "security2_module",
                "state": "loaded",
                "linkage": "shared",
                "source": "runtime-snapshot",
            },
            {
                "name": "status_module",
                "state": "absent",
                "linkage": "unknown",
                "source": "complete-snapshot-absence",
            },
        ],
    }


def _write_snapshot(
    tmp_path: Path,
    *,
    payload: dict[str, object] | None = None,
    name: str = "apache-modules.json",
) -> Path:
    path = tmp_path / name
    path.write_text(
        json.dumps(payload or _snapshot_payload(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def _policy_payload(
    *,
    host: str = "prod-web-01",
    snapshot_id: str = "prod-web-01-20260612",
    modules: dict[str, object] | None = None,
    benchmark_applicable: bool = True,
    benchmark_rationale: str | None = None,
    unlisted_loaded_modules: str = "fail",
) -> dict[str, object]:
    benchmark_scope: dict[str, object] = {
        "applicable": benchmark_applicable,
    }
    if benchmark_rationale is not None:
        benchmark_scope["rationale"] = benchmark_rationale
    return {
        "schema_version": 1,
        "policy_id": "apache-module-policy",
        "policy_version": "2026.06",
        "title": "Apache module inventory policy",
        "description": "Typed policy for explicit Apache module inventory evidence.",
        "defaults": {
            "disposition": "advisory",
            "evidence_expectation": "ledger-default",
            "include_unmapped_findings": True,
            "require_complete_execution_manifest": True,
        },
        "profiles": [
            {
                "profile_id": "apache-production",
                "title": "Apache production hosts",
                "selectors": [
                    {
                        "mode": "local",
                        "server_type": "apache",
                        "target_glob": "*httpd.conf",
                    }
                ],
                "sources": [
                    {
                        "source_id": SOURCE_ID,
                        "controls": [
                            {
                                "item_id": ITEM_ID,
                                "disposition": "required",
                                "evidence_expectation": "declared-direct",
                                "rationale": "Use explicit snapshot and module policy evidence.",
                            }
                        ],
                    }
                ],
            }
        ],
        "apache": {
            "module_inventory": {
                "policies": [
                    {
                        "id": "prod-web-01",
                        "selectors": {"host": host},
                        "inventory_snapshot_id": snapshot_id,
                        "unlisted_loaded_modules": unlisted_loaded_modules,
                        "benchmark_scope": {
                            "cis_apache_2_4_v2_3_0": benchmark_scope,
                        },
                        "modules": modules
                        if modules is not None
                        else {
                            "authz_core_module": {
                                "expectation": "required",
                                "rationale": "Core authorization support.",
                            },
                            "ssl_module": {
                                "expectation": "required",
                                "rationale": "HTTPS listener support.",
                            },
                            "security2_module": {
                                "expectation": "required",
                                "rationale": "Reviewed ModSecurity deployment.",
                            },
                            "status_module": {
                                "expectation": "forbidden",
                            },
                        },
                    }
                ]
            }
        },
        "provenance": {
            "owner": "Security Engineering",
            "approved_on": "2026-06-15",
            "change_ref": "SEC-2026-120",
        },
    }


def _write_policy(
    tmp_path: Path,
    *,
    payload: dict[str, object] | None = None,
    name: str = "audit-policy.yml",
) -> Path:
    path = tmp_path / name
    path.write_text(
        yaml.safe_dump(payload or _policy_payload(), sort_keys=False),
        encoding="utf-8",
    )
    return path


def _control_by_id(result, control_id: str = CONTROL_ID):
    return next(
        assessment for assessment in result.control_assessments if assessment.control_id == control_id
    )


def _build_assessment_status(
    tmp_path: Path,
    *,
    result,
    ledger_status: str = "full",
    absence_semantics: str = "control-pass",
) -> str:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id=SOURCE_ID,
        item_id=FULL_ITEM_ID,
        status=ledger_status,
        assessment_controls=(
            AssessableControlEvidence(
                control_id=CONTROL_ID,
                strength="direct",
                origin="declared",
                absence_semantics=absence_semantics,  # type: ignore[arg-type]
            ),
        ),
    )
    policy = resolve_policy(
        ledger,
        source_id=SOURCE_ID,
        item_id=FULL_ITEM_ID,
        mode="local",
        server_type="apache",
        target=result.target,
        target_glob="*httpd.conf",
    )
    synthetic_result = result_with_context(
        mode="local",
        target=result.target,
        server_type="apache",
        findings=[],
        issues=[],
        control_assessments=result.control_assessments,
        policy=policy,
        manifest=manifest_for(selected=(), completed=()),
    )
    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(synthetic_result))
    )
    assessment = build_control_assessment(report, ledger, registry)
    source = next(source for source in assessment.sources if source.source_id == SOURCE_ID)
    control = next(control for control in source.controls if control.item_id == FULL_ITEM_ID)
    return control.status


def test_load_apache_module_snapshot_normalizes_equivalent_aliases(tmp_path: Path) -> None:
    snapshot_path = _write_snapshot(
        tmp_path,
        payload=_snapshot_payload(
            modules=[
                {
                    "name": "ssl_module",
                    "state": "loaded",
                    "linkage": "shared",
                    "source": "runtime-snapshot",
                },
                {
                    "name": "modules/mod_ssl.so",
                    "state": "loaded",
                    "linkage": "shared",
                    "source": "runtime-snapshot",
                },
            ]
        ),
    )

    snapshot = load_apache_module_snapshot(snapshot_path)

    assert snapshot.modules[0].name == "ssl_module"
    assert len(snapshot.modules) == 1
    assert snapshot.modules[0].aliases == ("mod_ssl.c", "mod_ssl.so", "ssl", "ssl_module")


def test_load_apache_module_snapshot_normalizes_plain_shared_object_aliases(
    tmp_path: Path,
) -> None:
    snapshot_path = _write_snapshot(
        tmp_path,
        payload=_snapshot_payload(
            modules=[
                {
                    "name": "ssl_module",
                    "state": "loaded",
                    "linkage": "shared",
                    "source": "runtime-snapshot",
                },
                {
                    "name": "modules/ssl.so",
                    "state": "loaded",
                    "linkage": "shared",
                    "source": "runtime-snapshot",
                },
            ]
        ),
    )

    snapshot = load_apache_module_snapshot(snapshot_path)

    assert snapshot.modules[0].name == "ssl_module"
    assert len(snapshot.modules) == 1
    assert snapshot.modules[0].aliases == ("mod_ssl.c", "ssl", "ssl.so", "ssl_module")


def test_load_apache_module_snapshot_rejects_conflicting_aliases(tmp_path: Path) -> None:
    snapshot_path = _write_snapshot(
        tmp_path,
        payload=_snapshot_payload(
            modules=[
                {
                    "name": "ssl_module",
                    "state": "loaded",
                    "linkage": "shared",
                    "source": "runtime-snapshot",
                },
                {
                    "name": "mod_ssl.c",
                    "state": "absent",
                    "linkage": "unknown",
                    "source": "complete-snapshot-absence",
                },
            ]
        ),
    )

    with pytest.raises(ValueError, match="conflicting state"):
        load_apache_module_snapshot(snapshot_path)


def test_load_apache_module_snapshot_rejects_absent_in_partial_snapshot(tmp_path: Path) -> None:
    snapshot_path = _write_snapshot(
        tmp_path,
        payload=_snapshot_payload(
            completeness="partial",
            modules=[
                {
                    "name": "status_module",
                    "state": "absent",
                    "linkage": "unknown",
                    "source": "partial-snapshot",
                }
            ],
        ),
    )

    with pytest.raises(ValueError, match="absent modules require completeness state 'complete'"):
        load_apache_module_snapshot(snapshot_path)


def test_evaluate_apache_modules_marks_visible_loadmodule_conflict_indeterminate(
    tmp_path: Path,
) -> None:
    snapshot = load_apache_module_snapshot(_write_snapshot(tmp_path))
    policy = AuditPolicy.model_validate(_policy_payload())
    module_policy = policy.apache.module_inventory.policies[0]  # type: ignore[union-attr]
    config_ast = parse_apache_config(
        "\n".join(
            [
                "LoadModule authz_core_module modules/mod_authz_core.so",
                "LoadModule ssl_module modules/mod_ssl.so",
                "LoadModule status_module modules/mod_status.so",
            ]
        )
    )

    evaluation = evaluate_apache_modules(snapshot, module_policy, config_ast)

    assert evaluation.status == "indeterminate"
    assert "status_module" in evaluation.conflicting_modules
    assert any(
        comparison.module_name == "status_module"
        and comparison.predicate_result == "unknown"
        and comparison.config_visible is True
        and comparison.snapshot_state == "absent"
        for comparison in evaluation.comparisons
    )


def test_evaluate_apache_modules_missing_benchmark_scope_is_indeterminate(
    tmp_path: Path,
) -> None:
    snapshot = load_apache_module_snapshot(_write_snapshot(tmp_path))
    policy_payload = _policy_payload()
    del policy_payload["apache"]["module_inventory"]["policies"][0]["benchmark_scope"][
        "cis_apache_2_4_v2_3_0"
    ]
    policy = AuditPolicy.model_validate(policy_payload)
    module_policy = policy.apache.module_inventory.policies[0]  # type: ignore[union-attr]
    config_ast = parse_apache_config(
        "\n".join(
            [
                "LoadModule authz_core_module modules/mod_authz_core.so",
                "LoadModule ssl_module modules/mod_ssl.so",
            ]
        )
    )

    evaluation = evaluate_apache_modules(snapshot, module_policy, config_ast)

    assert evaluation.status == "indeterminate"
    assert evaluation.benchmark_applicable is None
    assert (
        "benchmark applicability was not declared for cis_apache_2_4_v2_3_0"
        in evaluation.missing_evidence
    )


def test_analyze_apache_config_with_snapshot_only_reports_evidence_without_control(
    tmp_path: Path,
) -> None:
    config_path = _write_config(
        tmp_path,
        "LoadModule authz_core_module modules/mod_authz_core.so",
        "LoadModule ssl_module modules/mod_ssl.so",
    )
    snapshot_path = _write_snapshot(tmp_path)

    result = analyze_apache_config(
        config_path,
        module_inventory_path=snapshot_path,
    )

    assert result.control_assessments == []
    assert result.metadata["apache_module_inventory"]["snapshot"]["snapshot_id"] == "prod-web-01-20260612"
    assert result.metadata["apache_module_inventory"]["policy_selected"] is None


def test_analyze_apache_config_with_policy_without_snapshot_is_indeterminate(
    tmp_path: Path,
) -> None:
    config_path = _write_config(tmp_path)
    policy_path = _write_policy(tmp_path)

    result = analyze_apache_config(config_path, policy=policy_path)

    assessment = _control_by_id(result)
    assert assessment.status == "indeterminate"
    assert assessment.metadata["inventory_id"] is None
    assert assessment.metadata["inventory_complete"] is False
    assert "module snapshot was not supplied" in assessment.summary.lower()


def test_analyze_apache_config_with_complete_snapshot_and_policy_can_drive_pass(
    tmp_path: Path,
) -> None:
    config_path = _write_config(
        tmp_path,
        "LoadModule authz_core_module modules/mod_authz_core.so",
        "LoadModule ssl_module modules/mod_ssl.so",
    )
    snapshot_path = _write_snapshot(tmp_path)
    policy_path = _write_policy(tmp_path)

    result = analyze_apache_config(
        config_path,
        policy=policy_path,
        module_inventory_path=snapshot_path,
    )

    assessment = _control_by_id(result)
    assert assessment.status == "pass"
    assert assessment.metadata["inventory_complete"] is True
    assert assessment.metadata["observations_complete"] is True
    assert _build_assessment_status(tmp_path, result=result) == "pass"


def test_loaded_allowed_module_prevents_positive_full_assessment(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        "LoadModule authz_core_module modules/mod_authz_core.so",
        "LoadModule ssl_module modules/mod_ssl.so",
        "LoadModule rewrite_module modules/mod_rewrite.so",
    )
    snapshot_path = _write_snapshot(
        tmp_path,
        payload=_snapshot_payload(
            modules=[
                {
                    "name": "authz_core_module",
                    "state": "loaded",
                    "linkage": "static",
                    "source": "runtime-snapshot",
                },
                {
                    "name": "ssl_module",
                    "state": "loaded",
                    "linkage": "shared",
                    "source": "runtime-snapshot",
                },
                {
                    "name": "security2_module",
                    "state": "loaded",
                    "linkage": "shared",
                    "source": "runtime-snapshot",
                },
                {
                    "name": "rewrite_module",
                    "state": "loaded",
                    "linkage": "shared",
                    "source": "runtime-snapshot",
                },
                {
                    "name": "status_module",
                    "state": "absent",
                    "linkage": "unknown",
                    "source": "complete-snapshot-absence",
                },
            ]
        ),
    )
    policy_path = _write_policy(
        tmp_path,
        payload=_policy_payload(
            modules={
                "authz_core_module": {
                    "expectation": "required",
                    "rationale": "Core authorization support.",
                },
                "ssl_module": {
                    "expectation": "required",
                    "rationale": "HTTPS listener support.",
                },
                "security2_module": {
                    "expectation": "required",
                    "rationale": "Reviewed ModSecurity deployment.",
                },
                "rewrite_module": {
                    "expectation": "allowed",
                    "rationale": "Reviewed redirect behavior.",
                },
                "status_module": {
                    "expectation": "forbidden",
                },
            }
        ),
    )

    result = analyze_apache_config(
        config_path,
        policy=policy_path,
        module_inventory_path=snapshot_path,
    )

    assessment = _control_by_id(result)
    assert assessment.status == "indeterminate"
    assert _build_assessment_status(tmp_path, result=result) == "indeterminate"


def test_validate_policy_rejects_duplicate_module_alias_keys(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path,
        payload=_policy_payload(
            modules={
                "ssl_module": {
                    "expectation": "required",
                    "rationale": "HTTPS listener support.",
                },
                "mod_ssl.c": {
                    "expectation": "forbidden",
                },
            }
        ),
    )

    with pytest.raises(ValueError, match="duplicate module aliases"):
        AuditPolicy.model_validate(yaml.safe_load(policy_path.read_text(encoding="utf-8")))


def test_analyze_apache_module_inventory_never_executes_binaries(tmp_path: Path, monkeypatch) -> None:
    config_path = _write_config(
        tmp_path,
        "LoadModule authz_core_module modules/mod_authz_core.so",
        "LoadModule ssl_module modules/mod_ssl.so",
    )
    snapshot_path = _write_snapshot(tmp_path)
    policy_path = _write_policy(tmp_path)

    def _explode(*_args, **_kwargs):
        raise AssertionError("Apache execution/discovery must not be used.")

    monkeypatch.setattr(subprocess, "run", _explode)
    monkeypatch.setattr(subprocess, "Popen", _explode)
    monkeypatch.setattr(os, "system", _explode)
    monkeypatch.setattr(os, "popen", _explode)
    monkeypatch.setattr(shutil, "which", _explode)

    result = analyze_apache_config(
        config_path,
        policy=policy_path,
        module_inventory_path=snapshot_path,
    )

    assert _control_by_id(result).status == "pass"
