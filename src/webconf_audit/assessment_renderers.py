"""Render versioned control assessments as deterministic text or JSON."""

from __future__ import annotations

from datetime import timezone
import json

from webconf_audit.assessment_models import (
    AssessmentEvidence,
    ControlAssessment,
    ControlAssessmentReport,
    MissingEvidence,
    SourceAssessment,
)

_STATUS_ORDER = {
    "fail": 0,
    "indeterminate": 1,
    "review": 2,
    "partial": 3,
    "pass": 4,
    "not-assessed": 5,
    "not-applicable": 6,
}


def render_assessment_json(assessment: ControlAssessmentReport) -> str:
    """Render the canonical assessment artifact as deterministic JSON."""
    payload = assessment.model_dump(mode="json")
    if isinstance(payload.get("generated_at"), str):
        payload["generated_at"] = (
            assessment.generated_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_assessment_text(assessment: ControlAssessmentReport) -> str:
    """Render a human-readable conservative assessment report."""
    lines = [
        "webconf-audit control assessment",
        f"Assessment schema: {assessment.schema_version}",
        f"Generated: {_safe(assessment.generated_at.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'))}",
        f"Policy: {_safe(assessment.inputs.policy_id)} v{_safe(assessment.inputs.policy_version)}",
        f"Report SHA256: {_safe(assessment.inputs.analysis_report_sha256)}",
        f"Ledger snapshot: {_safe(assessment.inputs.ledger_snapshot_id)}",
        f"Registry revision: {_safe(assessment.generator.registry_revision)}",
        "",
        "Summary:",
        (
            "  "
            f"pass={assessment.summary.passed} "
            f"fail={assessment.summary.failed} "
            f"partial={assessment.summary.partial} "
            f"review={assessment.summary.review} "
            f"indeterminate={assessment.summary.indeterminate} "
            f"not-assessed={assessment.summary.not_assessed} "
            f"not-applicable={assessment.summary.not_applicable}"
        ),
        "",
    ]
    if assessment.targets:
        lines.append("Targets:")
        for target in assessment.targets:
            lines.append(
                "  "
                f"{_safe(target.target_id)} "
                f"[{_safe(target.mode)}"
                f"{'/' + _safe(target.server_type) if target.server_type else ''}] "
                f"{_safe(target.display_name)}"
            )
        lines.append("")

    lines.append("Sources:")
    for source in assessment.sources:
        lines.extend(_source_lines(source))
    if assessment.issues:
        lines.extend(
            [
                "",
                "Issues:",
                *[
                    f"  [{issue.severity}] {_safe(issue.code)}: {_safe(issue.message)}"
                    for issue in assessment.issues
                ],
            ]
        )
    lines.extend(
        [
            "",
            "This assessment reports conservative evidence-backed statuses.",
            "It is not a compliance percentage, certification, or attestation.",
        ]
    )
    return "\n".join(lines) + "\n"


def _source_lines(source: SourceAssessment) -> list[str]:
    lines = [
        (
            f"  {_safe(source.title)} ({_safe(source.source_id)}) "
            f"- pass={source.summary.passed}, fail={source.summary.failed}, "
            f"partial={source.summary.partial}, review={source.summary.review}, "
            f"indeterminate={source.summary.indeterminate}, "
            f"not-assessed={source.summary.not_assessed}, "
            f"not-applicable={source.summary.not_applicable}"
        ),
        (
            "    "
            f"Product source coverage: full={source.coverage_summary.full}, "
            f"partial={source.coverage_summary.partial}, "
            f"policy-review={source.coverage_summary.policy_review}, "
            f"uncovered={source.coverage_summary.uncovered}, "
            f"full-percent={source.coverage_summary.full_percent:.1f}%"
        ),
    ]
    for control in sorted(source.controls, key=_control_sort_key):
        lines.extend(_control_lines(control))
    return lines


def _control_lines(control: ControlAssessment) -> list[str]:
    refs = "; ".join(_safe(reference.reference) for reference in control.references)
    lines = [
        (
            "    "
            f"[{control.status.upper()}] {_safe(control.item_id)} "
            f"{_safe(control.title)}"
        ),
        f"      References: {refs}",
        f"      Product source coverage: {_safe(control.ledger_status)}",
        f"      Target assessment: {_safe(control.status)}",
        f"      Policy disposition: {_safe(control.policy_disposition)}",
        f"      Rationale: {_safe(control.rationale)}",
    ]
    if control.evidence:
        lines.append("      Evidence:")
        for evidence in control.evidence:
            lines.append(f"        - {_evidence_line(evidence)}")
    if control.analyzer_evidence:
        lines.append("      Analyzer control evidence:")
        for evidence in control.analyzer_evidence:
            lines.append(
                "        - "
                f"control={_safe(evidence.control_id)} "
                f"target={_safe(evidence.target_id)} "
                f"status={_safe(evidence.status)} "
                f"mapping={_safe(evidence.mapping_strength)}/"
                f"{_safe(evidence.mapping_origin)} "
                f"inventory={_safe(evidence.inventory_id or '<none>')} "
                f"inventory-complete={_safe(evidence.inventory_complete)} "
                f"observations-complete={_safe(evidence.observations_complete)} "
                f"summary={_safe(evidence.summary)}"
            )
    if control.missing_evidence:
        lines.append("      Missing evidence:")
        for missing in control.missing_evidence:
            lines.append(f"        - {_missing_evidence_line(missing)}")
    if control.issues:
        lines.append(
            "      Issues: " + ", ".join(_safe(issue) for issue in control.issues)
        )
    return lines


def _evidence_line(evidence: AssessmentEvidence) -> str:
    finding_ids = ",".join(evidence.finding_ids) if evidence.finding_ids else "none"
    suppression = ",".join(_safe(ref) for ref in evidence.suppression_refs) or "none"
    facets = ",".join(_safe(facet) for facet in evidence.observed_facets) or "none"
    return (
        f"rule={_safe(evidence.rule_id)} target={_safe(evidence.target_id)} "
        f"state={_safe(evidence.execution_state)} "
        f"mapping={_safe(evidence.mapping_strength)}/{_safe(evidence.mapping_origin)} "
        f"absence={_safe(evidence.absence_semantics)} "
        f"findings={finding_ids} suppressed={str(evidence.suppressed).lower()} "
        f"suppression-refs={suppression} facets={facets} "
        f"note={_safe(evidence.note)}"
    )


def _missing_evidence_line(missing: MissingEvidence) -> str:
    rule = _safe(missing.rule_id) if missing.rule_id is not None else "<none>"
    return (
        f"rule={rule} expectation={_safe(missing.expectation)} "
        f"reason={_safe(missing.reason)} detail={_safe(missing.detail)}"
    )


def _control_sort_key(control: ControlAssessment) -> tuple[int, str]:
    return (_STATUS_ORDER[control.status], control.item_id)


def _safe(value: object) -> str:
    text = str(value)
    return "".join(
        character
        if " " <= character <= "~" or ord(character) >= 0x80
        else f"\\x{ord(character):02x}"
        for character in text
    )


__all__ = ["render_assessment_json", "render_assessment_text"]
