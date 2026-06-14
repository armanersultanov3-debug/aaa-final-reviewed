"""Build conservative control assessments from versioned analysis reports."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version as package_version
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError

from webconf_audit.assessment_models import (
    AnalysisReport,
    AnalysisReportFinding,
    AnalysisReportResult,
    AssessmentEvidence,
    AssessmentInputs,
    AssessmentIssue,
    AssessmentSummary,
    AssessmentTarget,
    ControlAssessment,
    ControlAssessmentReport,
    CoverageSummaryReference,
    FindingStandardReference,
    GeneratorIdentity,
    MissingEvidence,
    SourceAssessment,
    SuppressedFindingRecord,
)
from webconf_audit.audit_policy import resolve_audit_policy
from webconf_audit.coverage_ledger import render_coverage_json, validate_coverage_ledger
from webconf_audit.coverage_models import (
    AbsenceSemantics,
    CoverageItem,
    CoverageLedger,
    CoverageSource,
    MappingOrigin,
    MappingStrength,
)
from webconf_audit.execution_manifest import RuleExecutionManifest, registry_revision
from webconf_audit.models import AnalysisIssue, PolicyControlAssessment
from webconf_audit.policy_models import AuditPolicy, AuditTarget, ResolvedAuditPolicy, ResolvedControlPolicy
from webconf_audit.rule_registry import RuleRegistry

DEFAULT_ANALYSIS_REPORT_MAX_BYTES = 10 * 1024 * 1024
ASSESSMENT_SCHEMA_VERSION = 1
PACKAGE_NAME = "webconf-audit"
_STATUS_PRECEDENCE = {
    "fail": 0,
    "indeterminate": 1,
    "review": 2,
    "partial": 3,
    "pass": 4,
    "not-assessed": 5,
    "not-applicable": 6,
}
_SUMMARY_FIELD_BY_STATUS = {
    "pass": "passed",
    "fail": "failed",
    "partial": "partial",
    "review": "review",
    "indeterminate": "indeterminate",
    "not-assessed": "not_assessed",
    "not-applicable": "not_applicable",
}
_RULE_SKIP_REASON = {
    "mode-incompatible": "mode-unavailable",
    "server-incompatible": "server-unavailable",
    "input-unavailable": "skipped",
    "opt-in-not-selected": "skipped",
    "prerequisite-failed": "skipped",
}


class AnalysisReportLoadError(ValueError):
    """Raised when a report cannot be loaded into a trusted typed model."""

    def __init__(self, issue: AssessmentIssue) -> None:
        super().__init__(issue.message)
        self.issue = issue


class AssessmentBuildError(ValueError):
    """Raised when fatal assessment preconditions or inputs are not satisfied."""

    def __init__(self, issues: tuple[AssessmentIssue, ...]) -> None:
        super().__init__(issues[0].message if issues else "Assessment could not be built.")
        self.issues = issues


class _RuleDefinition:
    def __init__(
        self,
        *,
        rule_id: str,
        strength: MappingStrength,
        origin: MappingOrigin,
        absence_semantics: AbsenceSemantics,
        assessed_facets: tuple[str, ...] = (),
    ) -> None:
        self.rule_id = rule_id
        self.strength = strength
        self.origin = origin
        self.absence_semantics = absence_semantics
        self.assessed_facets = assessed_facets


def load_analysis_report(
    path: Path,
    *,
    max_bytes: int = DEFAULT_ANALYSIS_REPORT_MAX_BYTES,
) -> AnalysisReport:
    """Load a bounded JSON analysis report, preserving legacy-version detection."""
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise _load_issue(
            "analysis_report_not_found",
            f"Analysis report was not found: {path}",
        ) from exc
    except OSError as exc:
        raise _load_issue(
            "analysis_report_not_found",
            f"Analysis report could not be read: {path}",
        ) from exc
    if size > max_bytes:
        raise _load_issue(
            "analysis_report_too_large",
            f"Analysis report exceeds the {max_bytes}-byte limit: {path}",
        )
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise _load_issue(
            "analysis_report_not_found",
            f"Analysis report could not be read: {path}",
        ) from exc
    if len(raw_bytes) > max_bytes:
        raise _load_issue(
            "analysis_report_too_large",
            f"Analysis report exceeds the {max_bytes}-byte limit: {path}",
        )
    digest = sha256(raw_bytes).hexdigest()
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _load_issue(
            "analysis_report_json_invalid",
            f"Analysis report JSON is invalid: {exc}",
        ) from exc
    if not isinstance(raw, dict):
        raise _load_issue(
            "analysis_report_schema_invalid",
            "Analysis report root must be a JSON object.",
        )

    schema_version = raw.get("schema_version")
    if schema_version not in {None, 1}:
        raise _load_issue(
            "analysis_report_schema_unsupported",
            f"Unsupported analysis report schema_version: {schema_version!r}.",
        )

    results_raw = raw.get("results")
    if not isinstance(results_raw, list):
        raise _load_issue(
            "analysis_report_schema_invalid",
            "Analysis report must include a results array.",
        )

    top_level_findings = _parse_top_level_findings(raw.get("findings"), legacy=schema_version is None)
    top_level_issues = _parse_top_level_issues(raw.get("issues"))
    results = tuple(
        _parse_result_payload(result, legacy=schema_version is None)
        for result in results_raw
    )
    generator = None
    generated_at = None
    if schema_version == 1:
        try:
            generator = GeneratorIdentity.model_validate(raw.get("generator"))
            generated_at = datetime.fromisoformat(
                str(raw.get("generated_at")).replace("Z", "+00:00")
            )
        except (ValidationError, TypeError, ValueError) as exc:
            raise _load_issue(
                "analysis_report_schema_invalid",
                f"Analysis report generator metadata is invalid: {exc}",
            ) from exc
    else:
        generated_value = raw.get("generated_at")
        if isinstance(generated_value, str):
            try:
                generated_at = datetime.fromisoformat(generated_value.replace("Z", "+00:00"))
            except ValueError:
                generated_at = None

    return AnalysisReport(
        schema_version=schema_version,
        generator=generator,
        generated_at=generated_at,
        results=results,
        findings=top_level_findings,
        issues=top_level_issues,
        source_path=str(path),
        source_sha256=digest,
        load_issues=(),
    )


def verify_assessment_inputs(
    report: AnalysisReport,
    ledger: CoverageLedger,
    registry: RuleRegistry,
    verification_policy: AuditPolicy | None = None,
) -> tuple[AssessmentIssue, ...]:
    """Return all input-trust and compatibility issues for assessment."""
    issues: list[AssessmentIssue] = list(report.load_issues)
    ledger_keys = {
        (source.source_id, item.item_id)
        for source in ledger.sources
        for item in source.items
    }
    if report.schema_version is None:
        issues.append(
            AssessmentIssue(
                code="unassessable_legacy_report",
                severity="error",
                message=(
                    "Legacy analysis reports without schema_version cannot be used "
                    "for control assessment."
                ),
            )
        )
        return _sorted_unique_issues(issues)
    if report.generator is None:
        issues.append(
            AssessmentIssue(
                code="analysis_report_schema_invalid",
                severity="error",
                message="Analysis report generator metadata is missing.",
            )
        )
        return _sorted_unique_issues(issues)
    if report.generator.registry_revision != registry_revision(registry):
        issues.append(
            AssessmentIssue(
                code="registry_revision_mismatch",
                severity="error",
                message=(
                    "The analysis report registry revision does not match the "
                    "running package registry."
                ),
            )
        )

    for ledger_issue in validate_coverage_ledger(ledger, registry):
        issues.append(
            AssessmentIssue(
                code="ledger_validation_failed",
                severity="error",
                message=f"{ledger_issue.code}: {ledger_issue.message}",
                source_id=ledger_issue.source_id,
                item_id=ledger_issue.item_id,
                rule_id=ledger_issue.rule_id,
            )
        )

    top_level_ids: set[str] = set()
    for finding in report.findings:
        if finding.fingerprint in top_level_ids:
            issues.append(
                AssessmentIssue(
                    code="finding_id_duplicate",
                    severity="error",
                    message=f"Duplicate top-level finding fingerprint {finding.fingerprint!r}.",
                    rule_id=finding.rule_id,
                )
            )
        else:
            top_level_ids.add(finding.fingerprint)

    seen_finding_ids: set[str] = set()
    for result in report.results:
        issues.extend(result.metadata_issues)
        if result.audit_policy is None:
            issues.append(
                AssessmentIssue(
                    code="policy_metadata_missing",
                    severity="error",
                    message=(
                        f"Result target {result.target!r} does not include an embedded "
                        "resolved audit policy."
                    ),
                )
            )
        else:
            resolved_hash = _resolved_policy_sha(result.audit_policy)
            if resolved_hash != result.audit_policy.resolved_sha256:
                issues.append(
                    AssessmentIssue(
                        code="policy_hash_mismatch",
                        severity="error",
                        message=(
                            f"Embedded resolved policy hash does not match the policy "
                            f"payload for target {result.target!r}."
                        ),
                    )
                )
            for source_policy in result.audit_policy.sources:
                for control_policy in source_policy.controls:
                    if (source_policy.source_id, control_policy.item_id) in ledger_keys:
                        continue
                    issues.append(
                        AssessmentIssue(
                            code="policy_ledger_mismatch",
                            severity="error",
                            message=(
                                f"Embedded policy references item "
                                f"{control_policy.item_id!r} in source "
                                f"{source_policy.source_id!r}, which is not "
                                "present in the assessment ledger."
                            ),
                            source_id=source_policy.source_id,
                            item_id=control_policy.item_id,
                        )
                    )
            if verification_policy is not None:
                issues.extend(
                    _verify_policy_match(
                        verification_policy,
                        result,
                        ledger,
                    )
                )
        if result.rule_execution is None:
            issues.append(
                AssessmentIssue(
                    code="execution_manifest_missing",
                    severity="error",
                    message=(
                        f"Result target {result.target!r} does not include an embedded "
                        "execution manifest."
                    ),
                )
            )
            continue
        if report.generator.registry_revision != result.rule_execution.registry_revision:
            issues.append(
                AssessmentIssue(
                    code="registry_revision_mismatch",
                    severity="error",
                    message=(
                        f"Execution manifest registry revision does not match the "
                        f"report generator for target {result.target!r}."
                    ),
                )
            )

        for finding in result.findings:
            issues.extend(_verify_finding_payload(finding, registry))
            if finding.fingerprint in seen_finding_ids:
                issues.append(
                    AssessmentIssue(
                        code="finding_id_duplicate",
                        severity="error",
                        message=f"Duplicate finding fingerprint {finding.fingerprint!r}.",
                        rule_id=finding.rule_id,
                    )
                )
            else:
                seen_finding_ids.add(finding.fingerprint)
            if finding.rule_id not in result.rule_execution.selected_rule_ids:
                issues.append(
                    AssessmentIssue(
                        code="execution_manifest_invalid",
                        severity="error",
                        message=(
                            f"Finding {finding.fingerprint!r} references rule "
                            f"{finding.rule_id!r}, which was not selected in the "
                            "embedded execution manifest."
                        ),
                        rule_id=finding.rule_id,
                    )
                )
        for suppressed in result.suppressed_findings:
            issues.extend(_verify_finding_payload(suppressed.finding, registry))
            if not suppressed.source_path and suppressed.suppression_index < 1:
                issues.append(
                    AssessmentIssue(
                        code="suppression_reference_missing",
                        severity="error",
                        message=(
                            f"Suppressed finding {suppressed.fingerprint!r} is missing "
                            "stable suppression provenance."
                        ),
                        rule_id=suppressed.rule_id,
                    )
                )
            if suppressed.fingerprint in seen_finding_ids:
                issues.append(
                    AssessmentIssue(
                        code="finding_id_duplicate",
                        severity="error",
                        message=f"Duplicate finding fingerprint {suppressed.fingerprint!r}.",
                        rule_id=suppressed.rule_id,
                    )
                )
            else:
                seen_finding_ids.add(suppressed.fingerprint)
            if suppressed.rule_id not in result.rule_execution.selected_rule_ids:
                issues.append(
                    AssessmentIssue(
                        code="execution_manifest_invalid",
                        severity="error",
                        message=(
                            f"Suppressed finding {suppressed.fingerprint!r} references "
                            f"rule {suppressed.rule_id!r}, which was not selected in "
                            "the embedded execution manifest."
                        ),
                        rule_id=suppressed.rule_id,
                    )
                )

    return _sorted_unique_issues(issues)


def build_control_assessment(
    report: AnalysisReport,
    ledger: CoverageLedger,
    registry: RuleRegistry,
) -> ControlAssessmentReport:
    """Build a conservative control assessment artifact from trusted inputs."""
    issues = verify_assessment_inputs(report, ledger, registry)
    fatal = tuple(issue for issue in issues if issue.severity == "error")
    if fatal:
        raise AssessmentBuildError(fatal)
    if not report.results:
        raise AssessmentBuildError(
            (
                AssessmentIssue(
                    code="analysis_report_schema_invalid",
                    severity="error",
                    message="Analysis report contains no results to assess.",
                ),
            )
        )

    target_map = _build_targets(report.results)
    ledger_lookup = {
        (source.source_id, item.item_id): (source, item)
        for source in ledger.sources
        for item in source.items
    }
    result_controls: dict[tuple[str, str], list[ControlAssessment]] = defaultdict(list)
    report_issues: list[AssessmentIssue] = list(issues)

    for result in report.results:
        assert result.audit_policy is not None
        target_id = target_map[(result.mode, result.server_type, result.target)].target_id
        for source_policy in result.audit_policy.sources:
            for control_policy in source_policy.controls:
                key = (source_policy.source_id, control_policy.item_id)
                ledger_entry = ledger_lookup.get(key)
                if ledger_entry is None:
                    raise AssessmentBuildError(
                        (
                            AssessmentIssue(
                                code="policy_ledger_mismatch",
                                severity="error",
                                message=(
                                    f"Embedded policy references item "
                                    f"{control_policy.item_id!r} in source "
                                    f"{source_policy.source_id!r}, which is not "
                                    "present in the assessment ledger."
                                ),
                                source_id=source_policy.source_id,
                                item_id=control_policy.item_id,
                            ),
                        )
                    )
                ledger_source, ledger_item = ledger_entry
                control, control_issues = _assess_single_control(
                    result=result,
                    target_id=target_id,
                    source=ledger_source,
                    item=ledger_item,
                    control_policy=control_policy,
                )
                result_controls[(source_policy.source_id, control_policy.item_id)].append(control)
                report_issues.extend(control_issues)

    sources_payload: list[SourceAssessment] = []
    for source in ledger.sources:
        controls_payload: list[ControlAssessment] = []
        for item in source.items:
            key = (source.source_id, item.item_id)
            controls = result_controls.get(key)
            if not controls:
                continue
            controls_payload.append(_merge_control_assessments(controls))
        if not controls_payload:
            continue
        source_summary = _summary_from_statuses(control.status for control in controls_payload)
        sources_payload.append(
            SourceAssessment(
                source_id=source.source_id,
                title=source.title,
                version=source.version,
                coverage_summary=CoverageSummaryReference(
                    applicable=source.expected_summary.applicable,
                    full=source.expected_summary.full,
                    partial=source.expected_summary.partial,
                    policy_review=source.expected_summary.policy_review,
                    uncovered=source.expected_summary.uncovered,
                    full_percent=source.expected_summary.full_percent,
                ),
                controls=tuple(controls_payload),
                summary=source_summary,
            )
        )

    first_policy = report.results[0].audit_policy
    assert first_policy is not None
    first_manifest = report.results[0].rule_execution
    assert first_manifest is not None
    ledger_sha = sha256(render_coverage_json(ledger).encode("utf-8")).hexdigest()
    inputs = AssessmentInputs(
        analysis_report_sha256=report.source_sha256 or ("0" * 64),
        analysis_report_schema_version=report.schema_version,
        ledger_snapshot_id=ledger.snapshot.snapshot_id,
        ledger_sha256=ledger_sha,
        policy_id=first_policy.policy_id,
        policy_version=first_policy.policy_version,
        policy_raw_sha256=first_policy.raw_sha256,
        policy_resolved_sha256=first_policy.resolved_sha256,
        execution_manifest_schema_version=first_manifest.schema_version,
    )
    summary = _summary_from_statuses(
        control.status
        for source in sources_payload
        for control in source.controls
    )
    generator = GeneratorIdentity(
        package_name=PACKAGE_NAME,
        package_version=_package_version(),
        registry_revision=registry_revision(registry),
    )
    report_id = _assessment_report_id(
        analysis_report_sha256=inputs.analysis_report_sha256,
        ledger_sha256=inputs.ledger_sha256,
        policy_resolved_sha256=inputs.policy_resolved_sha256,
    )
    return ControlAssessmentReport(
        schema_version=ASSESSMENT_SCHEMA_VERSION,
        report_id=report_id,
        generated_at=datetime.now(timezone.utc),
        generator=generator,
        inputs=inputs,
        targets=tuple(target_map.values()),
        sources=tuple(sources_payload),
        summary=summary,
        issues=_sorted_unique_issues(report_issues),
    )


def _parse_top_level_findings(
    payload: object,
    *,
    legacy: bool,
) -> tuple[AnalysisReportFinding, ...]:
    if not isinstance(payload, list):
        return ()
    if legacy:
        return ()
    return tuple(AnalysisReportFinding.model_validate(entry) for entry in payload)


def _parse_top_level_issues(payload: object) -> tuple[AnalysisIssue, ...]:
    if not isinstance(payload, list):
        return ()
    return tuple(AnalysisIssue.model_validate(entry) for entry in payload)


def _parse_result_payload(raw: object, *, legacy: bool) -> AnalysisReportResult:
    if not isinstance(raw, dict):
        raise _load_issue(
            "analysis_report_schema_invalid",
            "Every analysis report result entry must be an object.",
        )
    try:
        mode = raw["mode"]
        target = raw["target"]
    except KeyError as exc:
        raise _load_issue(
            "analysis_report_schema_invalid",
            f"Analysis report result is missing required field: {exc.args[0]}",
        ) from exc
    findings: tuple[AnalysisReportFinding, ...]
    if legacy:
        findings = ()
    else:
        findings_raw = raw.get("findings")
        if not isinstance(findings_raw, list):
            raise _load_issue(
                "analysis_report_schema_invalid",
                "Analysis report result findings must be an array in schema version 1.",
            )
        findings = tuple(AnalysisReportFinding.model_validate(entry) for entry in findings_raw)
    issues_raw = raw.get("issues")
    if issues_raw is None:
        issues = ()
    elif isinstance(issues_raw, list):
        issues = tuple(AnalysisIssue.model_validate(entry) for entry in issues_raw)
    else:
        raise _load_issue(
            "analysis_report_schema_invalid",
            "Analysis report result issues must be an array.",
        )
    diagnostics_raw = raw.get("diagnostics")
    diagnostics = ()
    if diagnostics_raw is not None:
        if not isinstance(diagnostics_raw, list) or not all(
            isinstance(entry, str) for entry in diagnostics_raw
        ):
            raise _load_issue(
                "analysis_report_schema_invalid",
                "Analysis report result diagnostics must be an array of strings.",
            )
        diagnostics = tuple(diagnostics_raw)

    control_assessments: tuple[PolicyControlAssessment, ...] = ()
    control_assessments_raw = raw.get("control_assessments")
    if control_assessments_raw is not None:
        if not isinstance(control_assessments_raw, list):
            raise _load_issue(
                "analysis_report_schema_invalid",
                "Analysis report result control_assessments must be an array.",
            )
        control_assessments = tuple(
            PolicyControlAssessment.model_validate(entry)
            for entry in control_assessments_raw
        )

    audit_policy = None
    rule_execution = None
    suppressed_findings: tuple[SuppressedFindingRecord, ...] = ()
    metadata_issues: list[AssessmentIssue] = []
    metadata = raw.get("metadata")
    if isinstance(metadata, dict):
        if metadata.get("audit_policy") is not None:
            try:
                audit_policy = ResolvedAuditPolicy.model_validate(metadata["audit_policy"])
            except ValidationError as exc:
                metadata_issues.append(
                    AssessmentIssue(
                        code="policy_metadata_missing",
                        severity="error",
                        message=f"Embedded resolved audit policy is invalid: {exc}",
                    )
                )
        if metadata.get("rule_execution") is not None:
            try:
                rule_execution = RuleExecutionManifest.model_validate(metadata["rule_execution"])
            except ValidationError as exc:
                metadata_issues.append(
                    AssessmentIssue(
                        code="execution_manifest_invalid",
                        severity="error",
                        message=f"Embedded execution manifest is invalid: {exc}",
                    )
                )
        suppressed_raw = metadata.get("suppressed_findings")
        if suppressed_raw is not None:
            if not isinstance(suppressed_raw, list):
                metadata_issues.append(
                    AssessmentIssue(
                        code="analysis_report_schema_invalid",
                        severity="error",
                        message="suppressed_findings metadata must be an array.",
                    )
                )
            elif not legacy:
                try:
                    suppressed_findings = tuple(
                        SuppressedFindingRecord.model_validate(entry)
                        for entry in suppressed_raw
                    )
                except ValidationError as exc:
                    metadata_issues.append(
                        AssessmentIssue(
                            code="analysis_report_schema_invalid",
                            severity="error",
                            message=f"Suppressed finding payload is invalid: {exc}",
                        )
                    )
    elif metadata is not None:
        raise _load_issue(
            "analysis_report_schema_invalid",
            "Analysis report result metadata must be an object.",
        )

    return AnalysisReportResult(
        mode=mode,
        target=target,
        server_type=raw.get("server_type"),
        findings=findings,
        issues=issues,
        diagnostics=diagnostics,
        control_assessments=control_assessments,
        audit_policy=audit_policy,
        rule_execution=rule_execution,
        suppressed_findings=suppressed_findings,
        metadata_issues=tuple(metadata_issues),
    )


def _verify_policy_match(
    verification_policy: AuditPolicy,
    result: AnalysisReportResult,
    ledger: CoverageLedger,
) -> tuple[AssessmentIssue, ...]:
    if result.audit_policy is None:
        return ()
    try:
        resolved = resolve_audit_policy(
            verification_policy,
            AuditTarget(
                mode=result.mode,
                server_type=result.server_type,
                target=result.target,
            ),
            ledger,
        )
    except Exception as exc:
        return (
            AssessmentIssue(
                code="policy_verification_mismatch",
                severity="error",
                message=f"Verification policy could not be resolved: {exc}",
            ),
        )
    if (
        resolved.policy_id != result.audit_policy.policy_id
        or resolved.policy_version != result.audit_policy.policy_version
        or resolved.raw_sha256 != result.audit_policy.raw_sha256
        or resolved.resolved_sha256 != result.audit_policy.resolved_sha256
    ):
        return (
            AssessmentIssue(
                code="policy_verification_mismatch",
                severity="error",
                message=(
                    f"Verification policy does not match the embedded resolved "
                    f"policy for target {result.target!r}."
                ),
            ),
        )
    return ()


def _verify_finding_payload(
    finding: AnalysisReportFinding,
    registry: RuleRegistry,
) -> tuple[AssessmentIssue, ...]:
    meta = registry.get_meta(finding.rule_id)
    if meta is None:
        return (
            AssessmentIssue(
                code="finding_rule_unknown",
                severity="error",
                message=f"Unknown rule_id {finding.rule_id!r} in analysis report.",
                rule_id=finding.rule_id,
            ),
        )
    expected_primary = {_standard_key(ref) for ref in meta.standards}
    expected_secondary = {_standard_key(ref) for ref in meta.standards_secondary}
    actual_primary = {_report_standard_key(ref) for ref in finding.standards}
    actual_secondary = {_report_standard_key(ref) for ref in finding.standards_secondary}
    if actual_primary != expected_primary or actual_secondary != expected_secondary:
        return (
            AssessmentIssue(
                code="finding_mapping_mismatch",
                severity="error",
                message=(
                    f"Finding {finding.fingerprint!r} does not match live registry "
                    f"standard mappings for rule {finding.rule_id!r}."
                ),
                rule_id=finding.rule_id,
            ),
        )
    return ()


def _build_targets(
    results: tuple[AnalysisReportResult, ...],
) -> dict[tuple[str, str | None, str], AssessmentTarget]:
    targets: dict[tuple[str, str | None, str], AssessmentTarget] = {}
    for result in results:
        key = (result.mode, result.server_type, result.target)
        if key in targets:
            continue
        targets[key] = AssessmentTarget(
            target_id=_target_id(*key),
            display_name=_display_name(result.mode, result.target),
            mode=result.mode,
            server_type=result.server_type,
        )
    return targets


def _assess_single_control(
    *,
    result: AnalysisReportResult,
    target_id: str,
    source: CoverageSource,
    item: CoverageItem,
    control_policy: ResolvedControlPolicy,
) -> tuple[ControlAssessment, tuple[AssessmentIssue, ...]]:
    definitions = {definition.rule_id: definition for definition in _rule_definitions(item)}
    active_findings = _mapped_findings(result.findings, item)
    suppressed_findings = _mapped_suppressed_findings(result.suppressed_findings, item)
    for mapped in active_findings:
        definitions.setdefault(
            mapped["finding"].rule_id,
            _RuleDefinition(
                rule_id=mapped["finding"].rule_id,
                strength=mapped["strength"],
                origin=mapped["origin"],
                absence_semantics="none",
            ),
        )
    for mapped in suppressed_findings:
        definitions.setdefault(
            mapped["suppressed"].rule_id,
            _RuleDefinition(
                rule_id=mapped["suppressed"].rule_id,
                strength=mapped["strength"],
                origin=mapped["origin"],
                absence_semantics="none",
            ),
        )

    manifest = result.rule_execution
    assert manifest is not None
    completed = set(manifest.completed_rule_ids)
    skipped = {entry.rule_id: entry.reason for entry in manifest.skipped_rules}
    failed = {entry.rule_id: entry.issue_code for entry in manifest.failed_rules}
    selected = set(manifest.selected_rule_ids)
    evidence_entries: list[AssessmentEvidence] = []
    missing_evidence: list[MissingEvidence] = []
    control_issue_codes: set[str] = set()
    report_issues: list[AssessmentIssue] = []

    finding_map = _finding_map(active_findings)
    suppressed_map = _suppressed_finding_map(suppressed_findings)
    direct_negative = False
    partial_negative = False
    context_negative = False
    completed_positive_control_pass: set[str] = set()
    completed_positive_facet_pass: set[str] = set()

    for rule_id, definition in sorted(definitions.items()):
        active_for_rule = finding_map.get(rule_id, ())
        suppressed_for_rule = suppressed_map.get(rule_id, ())
        finding_ids = tuple(
            sorted(
                [entry["finding"].fingerprint for entry in active_for_rule]
                + [entry["suppressed"].fingerprint for entry in suppressed_for_rule]
            )
        )
        finding_severities = tuple(
            sorted(
                [entry["finding"].severity for entry in active_for_rule]
                + [entry["suppressed"].finding.severity for entry in suppressed_for_rule],
                key=lambda severity: ("info", "low", "medium", "high", "critical").index(severity),
            )
        )
        suppression_refs = tuple(
            sorted(
                {
                    _suppression_ref(entry["suppressed"])
                    for entry in suppressed_for_rule
                }
            )
        )
        observed_facets = (
            definition.assessed_facets
            if definition.absence_semantics == "facet-pass"
            and not finding_ids
            and rule_id in completed
            else ()
        )
        if definition.strength == "direct" and definition.origin == "declared" and finding_ids:
            direct_negative = True
        elif finding_ids and (
            definition.strength == "partial"
            or definition.origin == "derived"
        ):
            partial_negative = True
        elif finding_ids and definition.strength == "related":
            context_negative = True

        state: str | None
        note: str
        if rule_id in completed:
            state = "completed"
            if finding_ids:
                note = "Completed with mapped negative evidence."
            elif definition.absence_semantics == "control-pass":
                completed_positive_control_pass.add(rule_id)
                note = "Completed without finding; explicit control-pass semantics apply."
            elif definition.absence_semantics == "facet-pass":
                completed_positive_facet_pass.add(rule_id)
                note = "Completed without finding; named facet evidence observed."
            else:
                note = "Completed without finding; no positive pass semantics."
        elif rule_id in skipped:
            state = "skipped"
            note = f"Rule was skipped: {skipped[rule_id]}."
        elif rule_id in failed:
            state = "failed"
            note = f"Rule execution failed: {failed[rule_id]}."
        else:
            state = None
            note = ""

        if state is not None:
            evidence_entries.append(
                AssessmentEvidence(
                    rule_id=rule_id,
                    target_id=target_id,
                    mapping_strength=definition.strength,
                    mapping_origin=definition.origin,
                    absence_semantics=definition.absence_semantics,
                    execution_state=state,  # type: ignore[arg-type]
                    finding_ids=finding_ids,
                    finding_severities=finding_severities,
                    suppressed=bool(suppressed_for_rule),
                    suppression_refs=suppression_refs,
                    observed_facets=observed_facets,
                    note=note,
                )
            )

    required_rule_ids = control_policy.required_rule_ids
    required_positive_rule_ids = (
        required_rule_ids
        if required_rule_ids
        else tuple(
            rule_id
            for rule_id, definition in definitions.items()
            if definition.absence_semantics == "control-pass"
        )
    )
    if control_policy.disposition == "not-applicable":
        for mapped in active_findings:
            report_issues.append(
                AssessmentIssue(
                    code="out_of_policy_finding_retained",
                    severity="warning",
                    message=(
                        f"Finding {mapped['finding'].fingerprint!r} maps to control "
                        f"{item.item_id!r}, which policy marks not applicable."
                    ),
                    source_id=source.source_id,
                    item_id=item.item_id,
                    rule_id=mapped["finding"].rule_id,
                    target_id=target_id,
                )
            )
        for mapped in suppressed_findings:
            report_issues.append(
                AssessmentIssue(
                    code="out_of_policy_finding_retained",
                    severity="warning",
                    message=(
                        f"Suppressed finding {mapped['suppressed'].fingerprint!r} maps "
                        f"to control {item.item_id!r}, which policy marks not applicable."
                    ),
                    source_id=source.source_id,
                    item_id=item.item_id,
                    rule_id=mapped["suppressed"].rule_id,
                    target_id=target_id,
                )
            )
        return (
            ControlAssessment(
                source_id=source.source_id,
                item_id=item.item_id,
                title=item.title,
                references=item.references,
                ledger_status=item.status,
                policy_disposition=control_policy.disposition,
                status="not-applicable",
                rationale=control_policy.rationale,
                evidence=tuple(evidence_entries),
                missing_evidence=(),
                issues=(),
            ),
            tuple(report_issues),
        )

    if item.status == "uncovered":
        missing_evidence.append(
            MissingEvidence(
                rule_id=None,
                expectation=control_policy.evidence_expectation,
                reason="ledger-uncovered",
                detail="The canonical ledger marks this control as uncovered.",
            )
        )

    for rule_id in required_rule_ids:
        if rule_id in failed:
            missing_evidence.append(
                MissingEvidence(
                    rule_id=rule_id,
                    expectation=control_policy.evidence_expectation,
                    reason="execution-failed",
                    detail=f"Required rule failed with issue {failed[rule_id]!r}.",
                )
            )
        elif rule_id in skipped:
            missing_evidence.append(
                MissingEvidence(
                    rule_id=rule_id,
                    expectation=control_policy.evidence_expectation,
                    reason=_RULE_SKIP_REASON.get(skipped[rule_id], "skipped"),  # type: ignore[arg-type]
                    detail=f"Required rule was skipped: {skipped[rule_id]}.",
                )
            )
        elif rule_id not in selected:
            missing_evidence.append(
                MissingEvidence(
                    rule_id=rule_id,
                    expectation=control_policy.evidence_expectation,
                    reason="not-selected",
                    detail="Required rule was not selected in the execution manifest.",
                )
            )
        elif (
            rule_id in completed
            and not finding_map.get(rule_id)
            and not suppressed_map.get(rule_id)
            and definitions.get(rule_id, _RuleDefinition(
                rule_id=rule_id,
                strength="related",
                origin="declared",
                absence_semantics="none",
            )).absence_semantics
            == "none"
        ):
            missing_evidence.append(
                MissingEvidence(
                    rule_id=rule_id,
                    expectation=control_policy.evidence_expectation,
                    reason="no-pass-semantics",
                    detail=(
                        "Required rule completed without a finding, but the ledger "
                        "does not define automated pass semantics for its absence."
                    ),
                )
            )

    if control_policy.evidence_expectation == "operator-review":
        missing_evidence.append(
            MissingEvidence(
                rule_id=required_rule_ids[0] if required_rule_ids else None,
                expectation=control_policy.evidence_expectation,
                reason="operator-evidence-required",
                detail="Operator judgment remains required for this control.",
            )
        )

    pass_candidate = bool(required_positive_rule_ids) and all(
        rule_id in completed_positive_control_pass
        for rule_id in required_positive_rule_ids
    )
    if direct_negative and pass_candidate:
        control_issue_codes.add("conflicting_evidence")

    status = "not-assessed"
    rationale = "No applicable evidence was selected or completed for this control."
    if direct_negative:
        status = "fail"
        rationale = "Declared direct negative evidence shows the control is not met."
    elif any(entry.reason in {"execution-failed", "skipped", "mode-unavailable", "server-unavailable"} for entry in missing_evidence):
        status = "indeterminate"
        rationale = "Required evidence did not complete, so the control cannot be concluded safely."
    elif control_policy.disposition == "review" or item.status == "policy-review":
        status = "review"
        rationale = "Operator judgment is required for this control."
    elif partial_negative:
        status = "partial"
        rationale = "Only partial or derived negative evidence is available for this control."
    elif pass_candidate and item.status == "full":
        status = "pass"
        rationale = "Explicit declared direct control-pass evidence completed with no contradictory findings."
    elif pass_candidate and item.status == "partial":
        status = "partial"
        rationale = "Positive evidence completed, but the canonical ledger caps this control at partial."
    elif completed_positive_facet_pass or completed_positive_control_pass:
        status = "partial"
        rationale = "Completed evidence supports only a partial or facet-level conclusion."
    elif any(entry.reason == "no-pass-semantics" for entry in missing_evidence):
        status = "not-assessed"
        rationale = "Completed evidence exists, but no automated pass semantics are defined."
    elif item.status == "uncovered":
        status = "not-assessed"
        rationale = "The canonical ledger does not define an automated evidence path for this control."
    elif context_negative:
        status = "not-assessed"
        rationale = "Only related contextual evidence exists; it does not support a target conclusion."

    if control_policy.disposition == "advisory" and status == "pass":
        rationale = "Explicit declared direct control-pass evidence completed without contradictory findings."

    return (
        ControlAssessment(
            source_id=source.source_id,
            item_id=item.item_id,
            title=item.title,
            references=item.references,
            ledger_status=item.status,
            policy_disposition=control_policy.disposition,
            status=status,  # type: ignore[arg-type]
            rationale=rationale,
            evidence=tuple(sorted(evidence_entries, key=_evidence_sort_key)),
            missing_evidence=tuple(sorted(missing_evidence, key=_missing_evidence_sort_key)),
            issues=tuple(sorted(control_issue_codes)),
        ),
        tuple(report_issues),
    )


def _merge_control_assessments(
    controls: list[ControlAssessment],
) -> ControlAssessment:
    if len(controls) == 1:
        return controls[0]
    merged_status = min(controls, key=lambda control: _STATUS_PRECEDENCE[control.status]).status
    if all(control.status == "not-applicable" for control in controls):
        merged_status = "not-applicable"
    return controls[0].model_copy(
        update={
            "status": merged_status,
            "rationale": (
                f"Aggregated across {len(controls)} targets; worst observed status is "
                f"{merged_status}."
            ),
            "evidence": tuple(
                sorted(
                    (
                        evidence
                        for control in controls
                        for evidence in control.evidence
                    ),
                    key=_evidence_sort_key,
                )
            ),
            "missing_evidence": tuple(
                sorted(
                    (
                        missing
                        for control in controls
                        for missing in control.missing_evidence
                    ),
                    key=_missing_evidence_sort_key,
                )
            ),
            "issues": tuple(
                sorted(
                    {
                        issue
                        for control in controls
                        for issue in control.issues
                    }
                )
            ),
        }
    )


def _rule_definitions(item: CoverageItem) -> tuple[_RuleDefinition, ...]:
    explicit = {
        entry.rule_id: entry
        for entry in item.evidence.assessment_rules
    }
    definitions: list[_RuleDefinition] = []
    for rule_id in item.evidence.rule_ids:
        if rule_id in explicit:
            entry = explicit[rule_id]
            definitions.append(
                _RuleDefinition(
                    rule_id=entry.rule_id,
                    strength=entry.strength,
                    origin=entry.origin,
                    absence_semantics=entry.absence_semantics,
                    assessed_facets=entry.assessed_facets,
                )
            )
            continue
        claim = next(
            (
                claim
                for claim in item.evidence.registry_references
                if claim.rule_id == rule_id and _claim_matches_item(item, claim.standard, claim.reference)
            ),
            None,
        )
        if claim is None:
            continue
        definitions.append(
            _RuleDefinition(
                rule_id=claim.rule_id,
                strength=claim.strength,
                origin=claim.origin,
                absence_semantics="none",
            )
        )
    return tuple(definitions)


def _mapped_findings(
    findings: Iterable[AnalysisReportFinding],
    item: CoverageItem,
) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    for finding in findings:
        match = _matched_standard_reference(finding, item)
        if match is None:
            continue
        mapped.append(
            {
                "finding": finding,
                "strength": match.coverage,
                "origin": match.origin,
            }
        )
    return mapped


def _mapped_suppressed_findings(
    suppressed_findings: Iterable[SuppressedFindingRecord],
    item: CoverageItem,
) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    for suppressed in suppressed_findings:
        match = _matched_standard_reference(suppressed.finding, item)
        if match is None:
            continue
        mapped.append(
            {
                "suppressed": suppressed,
                "strength": match.coverage,
                "origin": match.origin,
            }
        )
    return mapped


def _matched_standard_reference(
    finding: AnalysisReportFinding,
    item: CoverageItem,
) -> FindingStandardReference | None:
    for reference in (*finding.standards, *finding.standards_secondary):
        if _claim_matches_item(item, reference.standard, reference.reference):
            return reference
    return None


def _claim_matches_item(item: CoverageItem, standard: str, reference: str) -> bool:
    return any(
        control.standard == standard
        and (
            control.reference == reference
            or reference in control.grouped_references
        )
        for control in item.references
    )


def _finding_map(mapped_findings: list[dict[str, Any]]) -> dict[str, tuple[dict[str, Any], ...]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in mapped_findings:
        grouped[entry["finding"].rule_id].append(entry)
    return {rule_id: tuple(entries) for rule_id, entries in grouped.items()}


def _suppressed_finding_map(
    mapped_findings: list[dict[str, Any]],
) -> dict[str, tuple[dict[str, Any], ...]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in mapped_findings:
        grouped[entry["suppressed"].rule_id].append(entry)
    return {rule_id: tuple(entries) for rule_id, entries in grouped.items()}


def _suppression_ref(suppressed: SuppressedFindingRecord) -> str:
    if suppressed.source_path:
        return f"{suppressed.source_path}#{suppressed.suppression_index}"
    return f"suppression#{suppressed.suppression_index}"


def _summary_from_statuses(statuses: Iterable[str]) -> AssessmentSummary:
    counts = Counter(statuses)
    return AssessmentSummary(
        total=sum(counts.values()),
        passed=counts["pass"],
        failed=counts["fail"],
        partial=counts["partial"],
        review=counts["review"],
        indeterminate=counts["indeterminate"],
        not_assessed=counts["not-assessed"],
        not_applicable=counts["not-applicable"],
    )


def _assessment_report_id(
    *,
    analysis_report_sha256: str,
    ledger_sha256: str,
    policy_resolved_sha256: str,
) -> str:
    digest = sha256(
        "\n".join(
            (
                analysis_report_sha256,
                ledger_sha256,
                policy_resolved_sha256,
            )
        ).encode("utf-8")
    ).hexdigest()
    return f"assessment-{digest[:24]}"


def _target_id(mode: str, server_type: str | None, target: str) -> str:
    digest = sha256(
        f"{mode}\0{server_type or ''}\0{target}".encode("utf-8")
    ).hexdigest()
    return f"target-{digest[:16]}"


def _display_name(mode: str, target: str) -> str:
    if mode != "external":
        return target
    parsed = urlsplit(target)
    if parsed.scheme and parsed.netloc:
        hostname = parsed.hostname or parsed.netloc
        port = f":{parsed.port}" if parsed.port is not None else ""
        return urlunsplit((parsed.scheme, f"{hostname}{port}", parsed.path, "", ""))
    return target


def _resolved_policy_sha(policy: ResolvedAuditPolicy) -> str:
    payload = policy.model_dump(mode="json")
    payload["resolved_sha256"] = None
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _standard_key(reference: Any) -> tuple[str, str, str, str, str | None, str | None]:
    return (
        reference.standard,
        reference.reference,
        reference.coverage,
        reference.origin,
        getattr(reference, "derived_from_standard", None),
        getattr(reference, "derived_from_reference", None),
    )


def _report_standard_key(
    reference: FindingStandardReference,
) -> tuple[str, str, str, str, str | None, str | None]:
    return (
        reference.standard,
        reference.reference,
        reference.coverage,
        reference.origin,
        reference.derived_from.standard if reference.derived_from is not None else None,
        reference.derived_from.reference if reference.derived_from is not None else None,
    )


def _evidence_sort_key(evidence: AssessmentEvidence) -> tuple[str, str, str]:
    return (evidence.target_id, evidence.rule_id, evidence.execution_state)


def _missing_evidence_sort_key(missing: MissingEvidence) -> tuple[str, str]:
    return (missing.rule_id or "", missing.reason)


def _sorted_unique_issues(
    issues: Iterable[AssessmentIssue],
) -> tuple[AssessmentIssue, ...]:
    unique = set(issues)
    return tuple(
        sorted(
            unique,
            key=lambda issue: (
                0 if issue.severity == "error" else 1,
                issue.code,
                issue.source_id or "",
                issue.item_id or "",
                issue.rule_id or "",
                issue.target_id or "",
                issue.message,
            ),
        )
    )


def _load_issue(code: str, message: str) -> AnalysisReportLoadError:
    return AnalysisReportLoadError(
        AssessmentIssue(
            code=code,
            severity="error",
            message=message,
        )
    )


def _package_version() -> str:
    try:
        return package_version(PACKAGE_NAME)
    except PackageNotFoundError:
        return "0.1.0"


__all__ = [
    "ASSESSMENT_SCHEMA_VERSION",
    "AnalysisReportLoadError",
    "AssessmentBuildError",
    "DEFAULT_ANALYSIS_REPORT_MAX_BYTES",
    "build_control_assessment",
    "load_analysis_report",
    "verify_assessment_inputs",
]
