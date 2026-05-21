"""Tests for rule severity profile coverage and catalog serialization."""

from __future__ import annotations

from webconf_audit.cli import _ensure_all_rules_loaded
from webconf_audit.models import Finding
from webconf_audit.rule_registry import registry
from webconf_audit.rule_severity import (
    CONFIDENCES,
    CONTEXT_DEPENDENCIES,
    EXPLOITABILITIES,
    EXPOSURES,
    IMPACTS,
)


def test_every_registered_rule_has_a_complete_severity_profile() -> None:
    _ensure_all_rules_loaded()

    for meta in registry.list_rules():
        profile = meta.severity_profile
        assert profile is not None, f"{meta.rule_id} is missing severity_profile"
        assert profile.impact, f"{meta.rule_id} has no impact axis"
        assert set(profile.impact) <= IMPACTS
        assert profile.exposure in EXPOSURES
        assert profile.exploitability in EXPLOITABILITIES
        assert profile.confidence in CONFIDENCES
        assert profile.context_dependency in CONTEXT_DEPENDENCIES


def test_direct_external_sensitive_artifact_profile_is_high_confidence() -> None:
    _ensure_all_rules_loaded()
    meta = registry.get_meta("external.git_metadata_exposed")
    assert meta is not None
    profile = meta.severity_profile
    assert profile is not None
    assert "confidentiality" in profile.impact
    assert profile.exposure == "external"
    assert profile.exploitability == "direct"
    assert profile.confidence == "high"


def test_policy_review_profile_marks_low_confidence_and_high_context() -> None:
    _ensure_all_rules_loaded()
    meta = registry.get_meta("nginx.limit_req_zone_rate_review")
    assert meta is not None
    profile = meta.severity_profile
    assert profile is not None
    assert "availability" in profile.impact
    assert profile.exploitability == "indirect"
    assert profile.confidence == "low"
    assert profile.context_dependency == "high"


def test_header_injection_profile_marks_integrity_and_direct_exploitation() -> None:
    _ensure_all_rules_loaded()
    meta = registry.get_meta("nginx.crlf_in_return")
    assert meta is not None
    profile = meta.severity_profile
    assert profile is not None
    assert "integrity" in profile.impact
    assert profile.exploitability == "direct"


def test_local_runtime_rule_profile_marks_mixed_exposure() -> None:
    _ensure_all_rules_loaded()
    meta = registry.get_meta("nginx.alias_without_trailing_slash")
    assert meta is not None
    profile = meta.severity_profile
    assert profile is not None
    assert "confidentiality" in profile.impact
    assert "integrity" in profile.impact
    assert profile.exposure == "mixed"
    assert profile.exploitability == "direct"


def test_registry_severities_are_calibrated_from_risk_profiles() -> None:
    _ensure_all_rules_loaded()

    expected = {
        "universal.tls_intent_without_config": "high",
        "universal.listen_on_all_interfaces": "info",
        "nginx.alias_without_trailing_slash": "high",
        "nginx.crlf_in_return": "high",
        "nginx.missing_access_log": "info",
        "nginx.missing_content_security_policy": "low",
        "apache.basic_auth_over_http": "high",
        "external.git_metadata_exposed": "high",
        "nginx.limit_req_zone_rate_review": "info",
    }
    for rule_id, severity in expected.items():
        meta = registry.get_meta(rule_id)
        assert meta is not None
        assert meta.severity == severity, rule_id


def test_direct_finding_construction_uses_calibrated_registry_severity() -> None:
    _ensure_all_rules_loaded()

    finding = Finding(
        rule_id="nginx.alias_without_trailing_slash",
        title="Alias path missing trailing slash",
        severity="medium",
        description="old inline severity",
        recommendation="Keep recommendation from rule implementation.",
    )

    assert finding.severity == "high"


def test_direct_finding_construction_preserves_contextual_severity_override() -> None:
    _ensure_all_rules_loaded()

    finding = Finding(
        rule_id="nginx.missing_limit_req",
        title="Missing limit_req directive",
        severity="medium",
        description="Contextual public autoindex finding.",
        recommendation="Add a limit_req directive.",
    )

    assert finding.severity == "medium"


def test_unknown_rule_finding_keeps_explicit_severity() -> None:
    finding = Finding(
        rule_id="custom.rule",
        title="Custom rule",
        severity="medium",
        description="Custom rule outside the project registry.",
        recommendation="Keep the explicit severity.",
    )

    assert finding.severity == "medium"
