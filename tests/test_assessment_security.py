from __future__ import annotations

from tests.assessment_helpers import (
    analysis_report_payload,
    attach_control_characters,
    ensure_rules_loaded,
    finding_for_rule,
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
from webconf_audit.rule_registry import registry


def test_assessment_text_escapes_terminal_control_characters(tmp_path) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.5-referrer-policy",
    )
    item = ledger.sources[0].items[0].model_copy(
        update={"title": attach_control_characters("Referrer policy")},
    )
    ledger = ledger.model_copy(
        update={
            "sources": (
                ledger.sources[0].model_copy(update={"items": (item,)}),
            )
        }
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

    text = render_assessment_text(build_control_assessment(report, ledger, registry))

    assert "\x1b" not in text
    assert "\\x1b" in text


def test_assessment_text_escapes_del_control_character(tmp_path) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.5-referrer-policy",
    )
    item = ledger.sources[0].items[0].model_copy(
        update={"title": "Referrer\x7fpolicy"},
    )
    ledger = ledger.model_copy(
        update={
            "sources": (
                ledger.sources[0].model_copy(update={"items": (item,)}),
            )
        }
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

    text = render_assessment_text(build_control_assessment(report, ledger, registry))

    assert "\x7f" not in text
    assert "\\x7f" in text


def test_assessment_artifact_does_not_copy_secret_bearing_finding_metadata(tmp_path) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.5-referrer-policy",
    )
    policy = resolve_policy(
        ledger,
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.5-referrer-policy",
    )
    result = result_with_context(
        findings=[
            finding_for_rule(
                "universal.missing_referrer_policy",
                metadata={"authorization": "Bearer super-secret-token"},
            )
        ],
        policy=policy,
        manifest=manifest_for(
            selected=("universal.missing_referrer_policy",),
            completed=("universal.missing_referrer_policy",),
        ),
    )
    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )

    rendered_json = render_assessment_json(build_control_assessment(report, ledger, registry))

    assert "super-secret-token" not in rendered_json
    assert "authorization" not in rendered_json
