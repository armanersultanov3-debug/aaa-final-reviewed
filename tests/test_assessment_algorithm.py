from __future__ import annotations

import json
from hashlib import sha256

import pytest

from tests.assessment_helpers import (
    analysis_report_payload,
    ensure_rules_loaded,
    finding_for_rule,
    make_suppression_for_finding,
    manifest_for,
    mutate_payload,
    resolve_policy,
    result_with_context,
    subset_ledger,
    write_payload,
)
from webconf_audit.assessment import (
    AssessmentBuildError,
    build_control_assessment,
    load_analysis_report,
    verify_assessment_inputs,
)
from webconf_audit.assessment_renderers import render_assessment_json
from webconf_audit.rule_registry import registry


def _control_status(report, source_id: str, item_id: str) -> str:
    source = next(source for source in report.sources if source.source_id == source_id)
    control = next(control for control in source.controls if control.item_id == item_id)
    return control.status


def _control(report, source_id: str, item_id: str):
    source = next(source for source in report.sources if source.source_id == source_id)
    return next(control for control in source.controls if control.item_id == item_id)


def test_verify_assessment_inputs_rejects_legacy_report_without_schema_version(
    tmp_path,
) -> None:
    payload = {
        "generated_at": "2026-06-14T00:00:00Z",
        "results": [],
        "findings": [],
        "issues": [],
        "summary": {
            "total_findings": 0,
            "total_issues": 0,
            "suppressed_findings": 0,
            "suppressed_duplicates": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "by_mode": {},
            "by_server_type": {},
            "targets_analyzed": [],
        },
    }
    report = load_analysis_report(write_payload(tmp_path / "legacy.json", payload))
    issues = verify_assessment_inputs(report, subset_ledger(source_id="owasp-asvs-5.0.0", item_id="asvs-3.4.5-referrer-policy"), registry)

    assert {issue.code for issue in issues} == {"unassessable_legacy_report"}


def test_control_assessment_no_finding_without_pass_semantics_stays_not_assessed(
    tmp_path,
) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.5-referrer-policy",
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
    assessment = build_control_assessment(report, ledger, registry)
    control = _control(assessment, "owasp-asvs-5.0.0", "asvs-3.4.5-referrer-policy")

    assert control.status == "not-assessed"
    assert any(entry.reason == "no-pass-semantics" for entry in control.missing_evidence)


def test_control_assessment_pass_requires_explicit_control_pass_semantics(tmp_path) -> None:
    from webconf_audit.coverage_models import AssessableRuleEvidence

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
    assessment = build_control_assessment(report, ledger, registry)

    assert _control_status(assessment, "owasp-asvs-5.0.0", "asvs-3.4.5-referrer-policy") == "pass"


def test_control_assessment_direct_finding_fails_even_when_suppressed(tmp_path) -> None:
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
    finding = finding_for_rule("universal.missing_referrer_policy")
    result = result_with_context(
        findings=[finding],
        policy=policy,
        manifest=manifest_for(
            selected=("universal.missing_referrer_policy",),
            completed=("universal.missing_referrer_policy",),
        ),
        suppressions=make_suppression_for_finding(finding),
    )

    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )
    assessment = build_control_assessment(report, ledger, registry)
    control = _control(assessment, "owasp-asvs-5.0.0", "asvs-3.4.5-referrer-policy")

    assert control.status == "fail"
    evidence = next(entry for entry in control.evidence if entry.rule_id == "universal.missing_referrer_policy")
    assert evidence.suppressed is True
    assert evidence.suppression_refs


def test_control_assessment_partial_mapping_finding_caps_status_to_partial(tmp_path) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.2-cors",
    )
    policy = resolve_policy(
        ledger,
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.2-cors",
    )
    result = result_with_context(
        mode="external",
        target="https://example.test",
        server_type=None,
        findings=[finding_for_rule("external.cors_wildcard_origin", mode="external", target="https://example.test")],
        policy=policy,
        manifest=manifest_for(
            selected=("external.cors_wildcard_origin",),
            completed=("external.cors_wildcard_origin",),
        ),
    )

    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )
    assessment = build_control_assessment(report, ledger, registry)

    assert _control_status(assessment, "owasp-asvs-5.0.0", "asvs-3.4.2-cors") == "partial"


def test_control_assessment_policy_review_control_reports_review(tmp_path) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="cis-nginx-3.0.0",
        item_id="nginx-4.1.12-http3-alt-svc",
    )
    policy = resolve_policy(
        ledger,
        source_id="cis-nginx-3.0.0",
        item_id="nginx-4.1.12-http3-alt-svc",
        disposition="review",
        evidence_expectation="operator-review",
        required_rule_ids=("nginx.http3_alt_svc_review",),
    )
    result = result_with_context(
        policy=policy,
        manifest=manifest_for(
            selected=("nginx.http3_alt_svc_review",),
            completed=("nginx.http3_alt_svc_review",),
        ),
    )

    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )
    assessment = build_control_assessment(report, ledger, registry)

    assert _control_status(assessment, "cis-nginx-3.0.0", "nginx-4.1.12-http3-alt-svc") == "review"


def test_control_assessment_required_skipped_rule_is_indeterminate(tmp_path) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.5-referrer-policy",
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
            skipped={"universal.missing_referrer_policy": "input-unavailable"},
        ),
    )

    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )
    assessment = build_control_assessment(report, ledger, registry)
    control = _control(assessment, "owasp-asvs-5.0.0", "asvs-3.4.5-referrer-policy")

    assert control.status == "indeterminate"
    assert any(entry.reason == "skipped" for entry in control.missing_evidence)


def test_control_assessment_uncovered_required_control_is_not_assessed(tmp_path) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="pci-dss-4.0.1",
        item_id="pci-8.3.5-password-reset-complexity",
    )
    policy = resolve_policy(
        ledger,
        source_id="pci-dss-4.0.1",
        item_id="pci-8.3.5-password-reset-complexity",
    )
    result = result_with_context(
        policy=policy,
        manifest=manifest_for(selected=()),
    )

    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )
    assessment = build_control_assessment(report, ledger, registry)
    control = _control(assessment, "pci-dss-4.0.1", "pci-8.3.5-password-reset-complexity")

    assert control.status == "not-assessed"
    assert any(entry.reason == "ledger-uncovered" for entry in control.missing_evidence)


def test_control_assessment_not_applicable_retains_out_of_policy_finding_as_issue(tmp_path) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.5-referrer-policy",
    )
    policy = resolve_policy(
        ledger,
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.5-referrer-policy",
        disposition="not-applicable",
    )
    result = result_with_context(
        findings=[finding_for_rule("universal.missing_referrer_policy")],
        policy=policy,
        manifest=manifest_for(
            selected=("universal.missing_referrer_policy",),
            completed=("universal.missing_referrer_policy",),
        ),
    )

    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )
    assessment = build_control_assessment(report, ledger, registry)

    assert _control_status(assessment, "owasp-asvs-5.0.0", "asvs-3.4.5-referrer-policy") == "not-applicable"
    assert any(issue.code == "out_of_policy_finding_retained" for issue in assessment.issues)


def test_control_assessment_csp_reporting_never_full_passes_from_partial_evidence(tmp_path) -> None:
    ensure_rules_loaded()
    ledger = subset_ledger(
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.7-csp-reporting",
    )
    policy = resolve_policy(
        ledger,
        source_id="owasp-asvs-5.0.0",
        item_id="asvs-3.4.7-csp-reporting",
        required_rule_ids=("external.content_security_policy_missing_reporting_endpoint",),
        mode="external",
        server_type=None,
        target="https://example.test",
        target_glob="https://example.test",
    )
    result = result_with_context(
        mode="external",
        target="https://example.test",
        server_type=None,
        policy=policy,
        manifest=manifest_for(
            selected=("external.content_security_policy_missing_reporting_endpoint",),
            completed=("external.content_security_policy_missing_reporting_endpoint",),
        ),
    )

    report = load_analysis_report(
        write_payload(tmp_path / "analysis.json", analysis_report_payload(result))
    )
    assessment = build_control_assessment(report, ledger, registry)

    assert _control_status(assessment, "owasp-asvs-5.0.0", "asvs-3.4.7-csp-reporting") != "pass"


def test_verify_assessment_inputs_rejects_stale_pci_combined_mapping(tmp_path) -> None:
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
        findings=[finding_for_rule("universal.missing_referrer_policy")],
        policy=policy,
        manifest=manifest_for(
            selected=("universal.missing_referrer_policy",),
            completed=("universal.missing_referrer_policy",),
        ),
    )

    payload = mutate_payload(
        result,
        lambda data: data["results"][0]["findings"][0].update(
            {
                "standards": [
                    {
                        "standard": "PCI DSS v4.0.1",
                        "reference": "Req. 8.3.5 / 8.3.6",
                        "coverage": "direct",
                        "origin": "declared",
                        "derived_from": None,
                    }
                ]
            }
        ),
    )
    report = load_analysis_report(write_payload(tmp_path / "analysis.json", payload))
    issues = verify_assessment_inputs(report, ledger, registry)

    assert any(issue.code == "finding_mapping_mismatch" for issue in issues)


def test_build_control_assessment_rejects_duplicate_finding_ids(tmp_path) -> None:
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
        findings=[finding_for_rule("universal.missing_referrer_policy")],
        policy=policy,
        manifest=manifest_for(
            selected=("universal.missing_referrer_policy",),
            completed=("universal.missing_referrer_policy",),
        ),
    )
    payload = mutate_payload(
        result,
        lambda data: data["findings"].append(dict(data["findings"][0])),
    )

    report = load_analysis_report(write_payload(tmp_path / "analysis.json", payload))
    with pytest.raises(AssessmentBuildError):
        build_control_assessment(report, ledger, registry)


def test_verify_assessment_inputs_rejects_embedded_policy_control_missing_from_ledger(
    tmp_path,
) -> None:
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
        policy=policy,
        manifest=manifest_for(selected=(), completed=()),
    )

    payload = mutate_payload(
        result,
        lambda data: data["results"][0]["metadata"]["audit_policy"]["sources"][0][
            "controls"
        ][0].update({"item_id": "missing-control"}),
    )
    embedded_policy = payload["results"][0]["metadata"]["audit_policy"]
    embedded_policy["resolved_sha256"] = _resolved_policy_sha_payload(embedded_policy)

    report = load_analysis_report(write_payload(tmp_path / "analysis.json", payload))
    issues = verify_assessment_inputs(report, ledger, registry)

    assert any(issue.code == "policy_ledger_mismatch" for issue in issues)
    with pytest.raises(AssessmentBuildError) as exc_info:
        build_control_assessment(report, ledger, registry)
    assert any(issue.code == "policy_ledger_mismatch" for issue in exc_info.value.issues)


def test_subset_ledger_rejects_unsupported_fixture_status() -> None:
    with pytest.raises(AssertionError, match="Unsupported status"):
        subset_ledger(
            source_id="owasp-asvs-5.0.0",
            item_id="asvs-3.4.5-referrer-policy",
            status="definitely-unsupported",
        )


def test_assessment_json_render_is_deterministic_except_generation_time(tmp_path) -> None:
    from webconf_audit.coverage_models import AssessableRuleEvidence

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

    first = json.loads(render_assessment_json(build_control_assessment(report, ledger, registry)))
    second = json.loads(render_assessment_json(build_control_assessment(report, ledger, registry)))
    first["generated_at"] = second["generated_at"] = None

    assert first == second


def _resolved_policy_sha_payload(policy_payload: dict[str, object]) -> str:
    payload = dict(policy_payload)
    payload["resolved_sha256"] = None
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()
