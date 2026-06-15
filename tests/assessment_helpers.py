from __future__ import annotations

from copy import deepcopy
from datetime import date
from decimal import Decimal
import json
from pathlib import Path

from webconf_audit.audit_policy import attach_audit_context, resolve_audit_policy
from webconf_audit.coverage_ledger import load_coverage_ledger
from webconf_audit.coverage_models import (
    AssessableControlEvidence,
    AssessableRuleEvidence,
    CoverageLedger,
    CoverageSubclaim,
    CoverageSummary,
)
from webconf_audit.execution_manifest import (
    RuleExecutionManifest,
    RuleExecutionRecorder,
    RuleSelection,
    build_rule_execution_manifest,
    registry_revision,
)
from webconf_audit.models import (
    AnalysisIssue,
    AnalysisResult,
    Finding,
    PolicyControlAssessment,
    SourceLocation,
)
from webconf_audit.policy_models import AuditPolicy, AuditTarget, ResolvedAuditPolicy
from webconf_audit.report import JsonFormatter, ReportData
from webconf_audit.rule_registry import registry
from webconf_audit.suppressions import Suppression, SuppressionSet, apply_suppressions


def ensure_rules_loaded() -> None:
    registry.ensure_loaded("webconf_audit.local.rules.universal")
    registry.ensure_loaded("webconf_audit.local.nginx.rules")
    registry.ensure_loaded("webconf_audit.local.apache.rules")
    registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
    registry.ensure_loaded("webconf_audit.local.iis.rules")
    registry.ensure_loaded("webconf_audit.external.rules")
    from webconf_audit.external.rules._runner import register_external_rule_metas

    register_external_rule_metas()


_ALLOWED_FIXTURE_STATUSES = {"full", "partial", "policy-review", "uncovered", "excluded"}


def _summary_for_status(status: str) -> CoverageSummary:
    if status not in _ALLOWED_FIXTURE_STATUSES:
        raise AssertionError(f"Unsupported status for test fixture: {status!r}")
    full = 1 if status == "full" else 0
    partial = 1 if status == "partial" else 0
    policy_review = 1 if status == "policy-review" else 0
    uncovered = 1 if status == "uncovered" else 0
    excluded = 1 if status == "excluded" else 0
    applicable = 0 if status == "excluded" else 1
    return CoverageSummary(
        applicable=applicable,
        full=full,
        partial=partial,
        policy_review=policy_review,
        uncovered=uncovered,
        excluded=excluded,
        full_percent=Decimal("100.0") if full else Decimal("0.0"),
    )


def subset_ledger(
    *,
    source_id: str,
    item_id: str,
    status: str | None = None,
    assessment_rules: tuple[AssessableRuleEvidence, ...] | None = None,
    assessment_controls: tuple[AssessableControlEvidence, ...] | None = None,
    subclaims: tuple[CoverageSubclaim, ...] | None = None,
) -> CoverageLedger:
    ensure_rules_loaded()
    ledger = load_coverage_ledger()
    source = next(source for source in ledger.sources if source.source_id == source_id)
    item = next(item for item in source.items if item.item_id == item_id)
    evidence_updates: dict[str, object] = {}
    if assessment_rules is not None:
        evidence_updates["assessment_rules"] = assessment_rules
    if assessment_controls is not None:
        evidence_updates["assessment_controls"] = assessment_controls
    if evidence_updates:
        item = item.model_copy(
            update={
                "evidence": item.evidence.model_copy(
                    update=evidence_updates
                )
            }
        )
    if subclaims is not None:
        item = item.model_copy(update={"subclaims": subclaims})
    if status is not None:
        if status not in _ALLOWED_FIXTURE_STATUSES:
            raise AssertionError(f"Unsupported status for test fixture: {status!r}")
        item = item.model_copy(update={"status": status})
    source = source.model_copy(
        update={
            "items": (item,),
            "expected_summary": _summary_for_status(item.status),
        }
    )
    return ledger.model_copy(
        update={
            "snapshot": ledger.snapshot.model_copy(update={"accepted_revisions": ()}),
            "sources": (source,),
        }
    )


def policy_for_control(
    *,
    source_id: str,
    item_id: str,
    disposition: str = "required",
    evidence_expectation: str = "ledger-default",
    required_rule_ids: tuple[str, ...] = (),
    mode: str = "local",
    server_type: str | None = "nginx",
    target_glob: str = "*nginx.conf",
) -> AuditPolicy:
    payload = {
        "schema_version": 1,
        "policy_id": "assessment-test-policy",
        "policy_version": "2026.06",
        "title": "Assessment test policy",
        "description": "Policy fixture for control assessment tests.",
        "defaults": {
            "disposition": "required",
            "evidence_expectation": "ledger-default",
            "include_unmapped_findings": True,
            "require_complete_execution_manifest": True,
        },
        "profiles": [
            {
                "profile_id": "assessment-target",
                "title": "Assessment target",
                "selectors": [
                    {
                        "mode": mode,
                        "server_type": server_type,
                        "target_glob": target_glob,
                    }
                ],
                "sources": [
                    {
                        "source_id": source_id,
                        "controls": [
                            {
                                "item_id": item_id,
                                "disposition": disposition,
                                "evidence_expectation": evidence_expectation,
                                "required_rule_ids": list(required_rule_ids),
                                "rationale": "Assessment test override.",
                            }
                        ],
                    }
                ],
            }
        ],
        "provenance": {
            "owner": "Security Engineering",
            "approved_on": "2026-06-14",
            "change_ref": "TEST-CTRL-ASSESS",
        },
    }
    return AuditPolicy.model_validate(payload)


def resolve_policy(
    ledger: CoverageLedger,
    *,
    source_id: str,
    item_id: str,
    disposition: str = "required",
    evidence_expectation: str = "ledger-default",
    required_rule_ids: tuple[str, ...] = (),
    mode: str = "local",
    server_type: str | None = "nginx",
    target: str = "/tmp/nginx.conf",
    target_glob: str = "*nginx.conf",
) -> ResolvedAuditPolicy:
    policy = policy_for_control(
        source_id=source_id,
        item_id=item_id,
        disposition=disposition,
        evidence_expectation=evidence_expectation,
        required_rule_ids=required_rule_ids,
        mode=mode,
        server_type=server_type,
        target_glob=target_glob,
    )
    return resolve_audit_policy(
        policy,
        AuditTarget(mode=mode, server_type=server_type, target=target),
        ledger,
    )


def manifest_for(
    *,
    selected: tuple[str, ...],
    completed: tuple[str, ...] = (),
    skipped: dict[str, str] | None = None,
    failed: dict[str, tuple[str, str]] | None = None,
) -> RuleExecutionManifest:
    ensure_rules_loaded()
    recorder = RuleExecutionRecorder()
    recorder.select_many(selected)
    for rule_id in completed:
        recorder.completed(rule_id)
    for rule_id, reason in (skipped or {}).items():
        recorder.skipped(rule_id, reason=reason)  # type: ignore[arg-type]
    for rule_id, (issue_code, stage) in (failed or {}).items():
        recorder.failed(rule_id, issue_code=issue_code, stage=stage)
    return build_rule_execution_manifest(
        RuleSelection(
            registry_revision=registry_revision(registry),
            selected_rule_ids=recorder.selected_rule_ids(),
        ),
        recorder.events(),
    )


def finding_for_rule(
    rule_id: str,
    *,
    mode: str = "local",
    target: str = "/tmp/nginx.conf",
    metadata: dict[str, object] | None = None,
) -> Finding:
    ensure_rules_loaded()
    meta = registry.get_meta(rule_id)
    if meta is None:
        raise AssertionError(f"Missing test rule metadata for {rule_id!r}.")
    location = (
        SourceLocation(mode="external", kind="url", target=target)
        if mode == "external"
        else SourceLocation(mode="local", kind="file", file_path=target, line=1)
    )
    return Finding(
        rule_id=meta.rule_id,
        title=meta.title,
        severity=meta.severity,
        description=meta.description,
        recommendation=meta.recommendation,
        location=location,
        metadata=metadata or {},
    )


def issue(
    code: str,
    *,
    level: str = "error",
    message: str | None = None,
    mode: str = "local",
    target: str = "/tmp/nginx.conf",
    metadata: dict[str, object] | None = None,
) -> AnalysisIssue:
    location = (
        SourceLocation(mode="external", kind="check", target=target)
        if mode == "external"
        else SourceLocation(mode="local", kind="file", file_path=target)
    )
    return AnalysisIssue(
        code=code,
        level=level,  # type: ignore[arg-type]
        message=message or code.replace("_", " "),
        location=location,
        metadata=metadata or {},
    )


def result_with_context(
    *,
    mode: str = "local",
    target: str = "/tmp/nginx.conf",
    server_type: str | None = "nginx",
    findings: list[Finding] | None = None,
    issues: list[AnalysisIssue] | None = None,
    control_assessments: list[PolicyControlAssessment] | None = None,
    policy: ResolvedAuditPolicy,
    manifest: RuleExecutionManifest,
    suppressions: SuppressionSet | None = None,
) -> AnalysisResult:
    result = AnalysisResult(
        mode=mode,  # type: ignore[arg-type]
        target=target,
        server_type=server_type,
        findings=findings or [],
        issues=issues or [],
        control_assessments=control_assessments or [],
    )
    if suppressions is not None:
        apply_suppressions(result, suppressions)
    return attach_audit_context(result, policy, manifest)


def make_suppression_for_finding(
    finding: Finding,
    *,
    result_target: str = "/tmp/nginx.conf",
    server_type: str | None = "nginx",
) -> SuppressionSet:
    marker_result = AnalysisResult(
        mode="local",
        target=result_target,
        server_type=server_type,
        findings=[finding],
    )
    from webconf_audit.fingerprints import finding_fingerprint

    return SuppressionSet(
        entries=(
            Suppression(
                index=1,
                rule_id=finding.rule_id,
                reason="Accepted for workflow tracking.",
                expires=date(2027, 1, 1),
                fingerprint=finding_fingerprint(marker_result, finding),
            ),
        ),
        source_path=".webconf-audit-ignore.yml",
    )


def analysis_report_json(result: AnalysisResult) -> str:
    return JsonFormatter().format(ReportData(results=[result]))


def analysis_report_payload(result: AnalysisResult) -> dict[str, object]:
    return json.loads(analysis_report_json(result))


def write_analysis_report(path: Path, result: AnalysisResult) -> Path:
    path.write_text(analysis_report_json(result), encoding="utf-8")
    return path


def mutate_payload(
    result: AnalysisResult,
    mutator,
) -> dict[str, object]:
    payload = analysis_report_payload(result)
    mutator(payload)
    return payload


def write_payload(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def attach_control_characters(text: str) -> str:
    return f"\x1b[31m{text}\x07"


def clone_result(result: AnalysisResult) -> AnalysisResult:
    return AnalysisResult.model_validate(deepcopy(result.model_dump(mode="json")))
