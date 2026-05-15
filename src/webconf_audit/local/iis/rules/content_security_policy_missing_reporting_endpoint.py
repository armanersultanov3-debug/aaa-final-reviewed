"""iis.content_security_policy_missing_reporting_endpoint -- Content-Security-Policy missing reporting endpoint."""

from __future__ import annotations

from webconf_audit.csp import content_security_policy_has_reporting_endpoint
from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.local.iis.rules.redirect_scope_utils import is_global_http_redirect_only
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "iis.content_security_policy_missing_reporting_endpoint"

_HEADER_NAME = "content-security-policy"


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy missing reporting endpoint",
    severity="low",
    description="Content-Security-Policy is configured without report-uri or report-to.",
    recommendation=(
        "Add a CSP report-to or report-uri directive pointing at a controlled "
        "reporting endpoint."
    ),
    category="local",
    server_type="iis",
    tags=("headers",),
    input_kind="effective",
    standards=(
        cwe(693),
        owasp_top10_2021("A05:2021"),
        asvs_5("3.4.7", coverage="partial", note="CSP reporting endpoint configured."),
    ),
    order=519,
)
def find_content_security_policy_missing_reporting_endpoint(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_findings(effective_config)
    return _raw_findings(doc)


def _effective_findings(effective_config: IISEffectiveConfig) -> list[Finding]:
    if is_global_http_redirect_only(effective_config):
        return []

    findings: list[Finding] = []
    for section in effective_config.all_sections:
        if section.section_path_suffix != "/customHeaders":
            continue
        if is_pure_inheritance(section):
            continue
        values = _active_csp_values(section.children)
        if any(
            not content_security_policy_has_reporting_endpoint(value)
            for value in values
        ):
            findings.append(_effective_missing_reporting_finding(section))
    return findings


def _raw_findings(doc: IISConfigDocument) -> list[Finding]:
    findings: list[Finding] = []
    for section in doc.sections:
        if section.tag != "customHeaders":
            continue
        values = _active_csp_values(section.children)
        if any(
            not content_security_policy_has_reporting_endpoint(value)
            for value in values
        ):
            findings.append(_raw_missing_reporting_finding(section))
    return findings


def _active_csp_values(children) -> list[str]:
    values: list[str] = []
    for child in children:
        tag = child.tag.lower()
        name = child.attributes.get("name", "").lower()
        if tag == "clear":
            values = []
            continue
        if name != _HEADER_NAME:
            continue
        if tag == "remove":
            values = []
        elif tag == "add":
            values.append(child.attributes.get("value", ""))
    return values


def _effective_missing_reporting_finding(section: IISEffectiveSection) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=RULE_ID,
        title="Content-Security-Policy missing reporting endpoint",
        severity="low",
        description=(
            f"The Content-Security-Policy custom header{ctx} does not include "
            "a report-uri or report-to directive, so policy violations are not "
            "reported."
        ),
        recommendation=(
            "Add a CSP report-to or report-uri directive pointing at a "
            "controlled reporting endpoint."
        ),
        location=effective_location(section),
    )


def _raw_missing_reporting_finding(section: IISSection) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Content-Security-Policy missing reporting endpoint",
        severity="low",
        description=(
            "The Content-Security-Policy custom header does not include a "
            "report-uri or report-to directive, so policy violations are not "
            "reported."
        ),
        recommendation=(
            "Add a CSP report-to or report-uri directive pointing at a "
            "controlled reporting endpoint."
        ),
        location=raw_location(section),
    )


__all__ = ["find_content_security_policy_missing_reporting_endpoint"]
