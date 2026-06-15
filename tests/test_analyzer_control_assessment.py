from __future__ import annotations

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
from webconf_audit.models import (
    ControlAssessmentEvidence,
    ControlAssessmentScope,
    PolicyControlAssessment,
)
from webconf_audit.rule_registry import registry

SOURCE_ID = "cis-nginx-3.0.0"
ITEM_ID = "nginx-4.1.2-trusted-certificate-chain"
FULL_SOURCE_ID = "nist-sp-800-52r2"
FULL_ITEM_ID = "nist-3.4-certificate-chain-quality"
CONTROL_ID = "external.tls_inventory"
TARGET = "tls-inventory/production-edge"


def _native_assessment(
    status: str,
    *,
    inventory_complete: bool = True,
    observations_complete: bool = True,
    metadata: dict[str, object] | None = None,
) -> PolicyControlAssessment:
    payload_metadata = {
        "inventory_id": "production-edge",
        "inventory_complete": inventory_complete,
        "observations_complete": observations_complete,
        "missing_evidence": [],
        "limitations": ["Bounded TLS observation."],
        "secret": "must-not-be-forwarded",
    }
    if metadata:
        payload_metadata.update(metadata)
    return PolicyControlAssessment(
        control_id=CONTROL_ID,
        title="Declared endpoint/SNI TLS inventory",
        status=status,  # type: ignore[arg-type]
        scope=ControlAssessmentScope(
            server_scope_id="production-edge",
            route_scope_id="api-primary",
            route_selector="api.example.test",
            server_name="api.example.test",
        ),
        summary=f"Inventory assessment is {status}.",
        evidence=(
            ControlAssessmentEvidence(
                kind="unsupported",
                status="observed",
                message="Certificate chain observation completed.",
                values=("api.example.test",),
            ),
        ),
        related_rule_ids=("external.cert_chain_incomplete",),
        policy_source="audit-policy.yml",
        metadata=payload_metadata,
    )


def _build(
    tmp_path,
    *,
    native_status: str,
    ledger_status: str = "partial",
    mapping_strength: str = "direct",
    mapping_origin: str = "declared",
    source_id: str = SOURCE_ID,
    item_id: str = ITEM_ID,
    required_rule_ids: tuple[str, ...] = (),
    control_assessments: list[PolicyControlAssessment] | None = None,
    manifest=None,
):
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id=source_id,
        item_id=item_id,
        status=ledger_status,
        assessment_controls=(
            AssessableControlEvidence(
                control_id=CONTROL_ID,
                strength=mapping_strength,  # type: ignore[arg-type]
                origin=mapping_origin,  # type: ignore[arg-type]
                absence_semantics=(
                    "control-pass"
                    if mapping_strength == "direct" and mapping_origin == "declared"
                    else "none"
                ),
            ),
        ),
    )
    policy = resolve_policy(
        ledger,
        source_id=source_id,
        item_id=item_id,
        mode="external",
        server_type=None,
        target=TARGET,
        target_glob="tls-inventory/*",
        required_rule_ids=required_rule_ids,
    )
    result = result_with_context(
        mode="external",
        target=TARGET,
        server_type=None,
        control_assessments=control_assessments
        if control_assessments is not None
        else [_native_assessment(native_status)],
        policy=policy,
        manifest=manifest or manifest_for(selected=(), completed=()),
    )
    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )
    assessment = build_control_assessment(report, ledger, registry)
    source = next(source for source in assessment.sources if source.source_id == source_id)
    return next(control for control in source.controls if control.item_id == item_id)


def test_direct_native_pass_is_capped_by_partial_ledger(tmp_path) -> None:
    control = _build(tmp_path, native_status="pass")

    assert control.status == "partial"
    assert control.analyzer_evidence[0].control_id == CONTROL_ID
    assert control.analyzer_evidence[0].inventory_id == "production-edge"
    assert control.analyzer_evidence[0].inventory_complete is True
    assert control.analyzer_evidence[0].observations_complete is True
    assert "secret" not in control.analyzer_evidence[0].model_dump(mode="json")


def test_direct_native_pass_requires_full_ledger_for_pass(tmp_path) -> None:
    control = _build(
        tmp_path,
        native_status="pass",
        ledger_status="full",
        source_id=FULL_SOURCE_ID,
        item_id=FULL_ITEM_ID,
    )

    assert control.status == "pass"


def test_direct_native_fail_produces_fail(tmp_path) -> None:
    control = _build(tmp_path, native_status="fail")

    assert control.status == "fail"
    assert control.analyzer_evidence[0].status == "fail"


def test_native_indeterminate_prevents_positive_conclusion(tmp_path) -> None:
    control = _build(
        tmp_path,
        native_status="indeterminate",
        ledger_status="full",
        source_id=FULL_SOURCE_ID,
        item_id=FULL_ITEM_ID,
    )

    assert control.status == "indeterminate"


def test_related_or_derived_native_result_cannot_independently_pass_or_fail(
    tmp_path,
) -> None:
    related = _build(
        tmp_path,
        native_status="fail",
        ledger_status="full",
        mapping_strength="related",
        source_id=FULL_SOURCE_ID,
        item_id=FULL_ITEM_ID,
    )
    derived = _build(
        tmp_path,
        native_status="pass",
        ledger_status="full",
        mapping_origin="derived",
        source_id=FULL_SOURCE_ID,
        item_id=FULL_ITEM_ID,
    )

    assert related.status == "not-assessed"
    assert derived.status == "not-assessed"


def test_unmapped_native_assessment_does_not_change_existing_result(tmp_path) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id=SOURCE_ID,
        item_id=ITEM_ID,
        status="partial",
        assessment_controls=(),
        subclaims=(),
    )
    policy = resolve_policy(
        ledger,
        source_id=SOURCE_ID,
        item_id=ITEM_ID,
        mode="external",
        server_type=None,
        target=TARGET,
        target_glob="tls-inventory/*",
    )
    result = result_with_context(
        mode="external",
        target=TARGET,
        server_type=None,
        control_assessments=[_native_assessment("fail")],
        policy=policy,
        manifest=manifest_for(selected=(), completed=()),
    )
    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )
    assessment = build_control_assessment(report, ledger, registry)
    source = next(source for source in assessment.sources if source.source_id == SOURCE_ID)
    control = next(control for control in source.controls if control.item_id == ITEM_ID)

    assert control.status == "not-assessed"
    assert control.analyzer_evidence == ()


def test_required_execution_failure_outranks_native_pass(tmp_path) -> None:
    control = _build(
        tmp_path,
        native_status="pass",
        ledger_status="full",
        source_id=FULL_SOURCE_ID,
        item_id=FULL_ITEM_ID,
        required_rule_ids=("external.cert_chain_incomplete",),
        manifest=manifest_for(
            selected=("external.cert_chain_incomplete",),
            failed={
                "external.cert_chain_incomplete": (
                    "tls_probe_failed",
                    "tls-inventory",
                )
            },
        ),
    )

    assert control.status == "indeterminate"
