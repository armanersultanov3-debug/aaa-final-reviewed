from __future__ import annotations

from webconf_audit.hsts_policy import hsts_policy_reason
from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISChildElement, IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    is_pure_inheritance,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.hsts_header_unsafe"
TITLE = "Strict-Transport-Security header is weak"
DESCRIPTION = "IIS sets Strict-Transport-Security to an invalid or weak value."
RECOMMENDATION = (
    'Set Strict-Transport-Security to "max-age=31536000; includeSubDomains".'
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="iis",
    input_kind="effective",
    tags=("headers", "tls"),
    order=543,
)
def find_hsts_header_unsafe(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_findings(effective_config)
    return _raw_findings(doc)


def _effective_findings(effective_config: IISEffectiveConfig) -> list[Finding]:
    findings: list[Finding] = []
    for section in effective_config.all_sections:
        if section.section_path_suffix != "/customHeaders":
            continue
        if is_pure_inheritance(section):
            continue
        child = _hsts_child(section.children)
        if child is None:
            continue
        reason = hsts_policy_reason(child.attributes.get("value", ""))
        if reason is None:
            continue
        findings.append(_effective_finding(section, child, reason))
    return findings


def _raw_findings(doc: IISConfigDocument) -> list[Finding]:
    findings: list[Finding] = []
    for section in doc.sections:
        if section.tag != "customHeaders":
            continue
        child = _hsts_child(section.children)
        if child is None:
            continue
        reason = hsts_policy_reason(child.attributes.get("value", ""))
        if reason is None:
            continue
        findings.append(_raw_finding(section, child, reason))
    return findings


def _hsts_child(children: list[IISChildElement]) -> IISChildElement | None:
    for child in children:
        if child.tag.lower() != "add":
            continue
        if child.attributes.get("name", "").lower() == "strict-transport-security":
            return child
    return None


def _effective_finding(
    section: IISEffectiveSection,
    child: IISChildElement,
    reason: str,
) -> Finding:
    value = child.attributes.get("value", "")
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="medium",
        description=f"IIS sets Strict-Transport-Security to {value!r}: {reason}.",
        recommendation=RECOMMENDATION,
        location=effective_location(section),
    )


def _raw_finding(section: IISSection, child: IISChildElement, reason: str) -> Finding:
    value = child.attributes.get("value", "")
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="medium",
        description=f"IIS sets Strict-Transport-Security to {value!r}: {reason}.",
        recommendation=RECOMMENDATION,
        location=raw_location(section),
    )


__all__ = ["find_hsts_header_unsafe"]
