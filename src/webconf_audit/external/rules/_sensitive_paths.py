from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.rules._helpers import _is_accessible_status
from webconf_audit.external.safe_probe_catalog import (
    CONDITIONAL_SAFE_PROBE_CONFIDENCES,
    SAFE_PATH_RULES,
    SafePathRule,
    body_matcher_matches,
)
from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import SensitivePathProbe, ServerIdentification


def _rule_matches_probe(rule: SafePathRule, probe: "SensitivePathProbe") -> bool:
    if probe.path not in rule.paths:
        return False
    if not _is_accessible_status(probe.status_code):
        return False
    return all(
        body_matcher_matches(matcher, probe.body_snippet)
        for matcher in rule.body_matchers
    )


def _rule_suppressed_by_identification(
    rule: SafePathRule,
    probe: "SensitivePathProbe",
    server_identification: "ServerIdentification | None",
) -> bool:
    if server_identification is None:
        return False
    if server_identification.confidence not in CONDITIONAL_SAFE_PROBE_CONFIDENCES:
        return False

    for suppression in rule.suppress_when_identified:
        if server_identification.server_type != suppression.server_type:
            continue
        if not suppression.paths or probe.path in suppression.paths:
            return True
    return False


def _finding_for_rule(rule: SafePathRule, probe: "SensitivePathProbe") -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        description=rule.description,
        recommendation=rule.recommendation,
        location=SourceLocation(
            mode="external",
            kind="url",
            target=probe.url,
            details=probe.path,
        ),
    )


def collect_sensitive_path_findings(
    path_probes: list["SensitivePathProbe"],
    server_identification: "ServerIdentification | None" = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for rule in SAFE_PATH_RULES:
        for probe in path_probes:
            if not _rule_matches_probe(rule, probe):
                continue
            if _rule_suppressed_by_identification(
                rule,
                probe,
                server_identification,
            ):
                continue
            findings.append(_finding_for_rule(rule, probe))
    return findings


__all__ = [
    "collect_sensitive_path_findings",
]
