from __future__ import annotations

import json

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
from webconf_audit.assessment_renderers import (
    render_assessment_json,
    render_assessment_text,
)
from webconf_audit.coverage_models import AssessableRuleEvidence
from webconf_audit.rule_registry import registry


def _pass_assessment(tmp_path):
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.5-referrer-policy",
        assessment_rules=(
            AssessableRuleEvidence(
                rule_id="universal.missing_referrer_policy",
                strength="direct",
                origin="declared",
                absence_semantics="control-pass",
            ),
        ),
    )
    policy = resolve_policy(
        ledger,
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.5-referrer-policy",
        required_rule_ids=("universal.missing_referrer_policy",),
    )
    result = result_with_context(
        policy=policy,
        manifest=manifest_for(
            selected=("universal.missing_referrer_policy",),
            completed=("universal.missing_referrer_policy",),
        ),
    )
    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )
    return build_control_assessment(report, ledger, registry)


def test_render_assessment_json_includes_versioned_provenance(tmp_path) -> None:
    assessment = _pass_assessment(tmp_path)

    payload = json.loads(render_assessment_json(assessment))

    assert payload["schema_version"] == 1
    assert payload["generator"]["package_name"] == "webconf-audit"
    assert payload["inputs"]["analysis_report_schema_version"] == 1
    assert payload["sources"][0]["controls"][0]["status"] == "pass"


def test_render_assessment_text_separates_product_coverage_from_target_status(tmp_path) -> None:
    assessment = _pass_assessment(tmp_path)

    text = render_assessment_text(assessment)

    assert "Product source coverage:" in text
    assert "Target assessment:" in text
    assert "certification" in text.lower()
    assert "compliance percentage" in text.lower()
