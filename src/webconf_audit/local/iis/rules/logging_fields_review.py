"""iis.logging_fields_review -- policy-review rule.

Surfaces the current ``<httpLogging>`` configuration so an operator
can review whether the logging posture matches the organisation's
SIEM / retention policy. Existing rules already handle the "disabled"
and "missing" cases as medium-severity findings; this rule
complements them by listing the configured state for human review.

Opt-in: only runs when ``--enable-policy-review`` is set on the CLI.
"""

from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.logging_fields_review"


@rule(
    rule_id=RULE_ID,
    title="IIS HTTP logging posture needs operator review",
    severity="info",
    description=(
        "IIS HTTP logging is configured. The chosen logFormat (W3C / IIS / "
        "NCSA / Custom), selectedFields, and any selectiveLogging modes "
        "determine what reaches the SIEM and need operator review against "
        "the logging policy."
    ),
    recommendation=(
        "Confirm that the configured httpLogging settings (and any "
        "sites/siteDefaults/logFile overrides) capture the audit fields "
        "your SIEM and retention policy require. Document the choice or "
        "extend the format if required fields are missing."
    ),
    category="local",
    server_type="iis",
    input_kind="effective",
    tags=("policy-review", "logging"),
    order=560,
)
def find_logging_fields_review(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_findings(effective_config)
    return _raw_findings(doc)


def _effective_findings(effective_config: IISEffectiveConfig) -> list[Finding]:
    findings: list[Finding] = []
    for section in effective_config.all_sections:
        if section.section_path_suffix != "/httpLogging":
            continue
        if is_pure_inheritance(section):
            continue
        if section.attributes.get("dontLog", "").lower() == "true":
            # The active logging-disabled case is already covered by
            # ``iis.logging_not_configured`` at medium severity; do not
            # double-surface it as a policy-review item.
            continue
        findings.append(_effective_finding(section))
    return findings


def _raw_findings(doc: IISConfigDocument) -> list[Finding]:
    findings: list[Finding] = []
    for section in doc.sections:
        if section.tag != "httpLogging":
            continue
        if section.attributes.get("dontLog", "").lower() == "true":
            continue
        findings.append(_raw_finding(section))
    return findings


def _effective_finding(section: IISEffectiveSection) -> Finding:
    ctx = location_context(section)
    attrs = _format_attributes(section.attributes)
    return Finding(
        rule_id=RULE_ID,
        title="IIS HTTP logging posture needs operator review",
        severity="info",
        description=(
            f"IIS HTTP logging is configured{ctx} with: {attrs}. Confirm "
            "that the selected log format and fields satisfy your SIEM "
            "and retention policy."
        ),
        recommendation=(
            "Document the configured logging posture or extend the "
            "logFormat / selectedFields if required audit fields are missing."
        ),
        location=effective_location(section),
    )


def _raw_finding(section: IISSection) -> Finding:
    attrs = _format_attributes(section.attributes)
    return Finding(
        rule_id=RULE_ID,
        title="IIS HTTP logging posture needs operator review",
        severity="info",
        description=(
            f"IIS HTTP logging is configured with: {attrs}. Confirm that "
            "the selected log format and fields satisfy your SIEM and "
            "retention policy."
        ),
        recommendation=(
            "Document the configured logging posture or extend the "
            "logFormat / selectedFields if required audit fields are missing."
        ),
        location=raw_location(section),
    )


def _format_attributes(attributes: dict[str, str]) -> str:
    if not attributes:
        return "default IIS settings"
    parts = [f'{key}="{value}"' for key, value in sorted(attributes.items())]
    return " ".join(parts)


__all__ = ["find_logging_fields_review"]
