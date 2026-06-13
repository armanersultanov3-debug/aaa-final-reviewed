from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webconf_audit.assessment_models import (
    AssessmentInputs,
    AssessmentSummary,
    ControlAssessmentReport,
    GeneratorIdentity,
)


def test_assessment_summary_rejects_invalid_totals() -> None:
    with pytest.raises(ValueError, match="totals do not add up"):
        AssessmentSummary(
            total=2,
            passed=1,
            failed=0,
            partial=0,
            review=0,
            indeterminate=0,
            not_assessed=0,
            not_applicable=0,
        )


def test_control_assessment_report_accepts_versioned_minimal_payload() -> None:
    report = ControlAssessmentReport(
        schema_version=1,
        report_id="assessment-test",
        generated_at=datetime.now(timezone.utc),
        generator=GeneratorIdentity(
            package_name="webconf-audit",
            package_version="0.1.0",
            registry_revision="registry:test",
        ),
        inputs=AssessmentInputs(
            analysis_report_sha256="a" * 64,
            analysis_report_schema_version=1,
            ledger_snapshot_id="snapshot-test",
            ledger_sha256="b" * 64,
            policy_id="policy-test",
            policy_version="2026.06",
            policy_raw_sha256="c" * 64,
            policy_resolved_sha256="d" * 64,
            execution_manifest_schema_version=1,
        ),
        targets=(),
        sources=(),
        summary=AssessmentSummary(
            total=0,
            passed=0,
            failed=0,
            partial=0,
            review=0,
            indeterminate=0,
            not_assessed=0,
            not_applicable=0,
        ),
        issues=(),
    )

    assert report.schema_version == 1
    assert report.summary.total == 0
