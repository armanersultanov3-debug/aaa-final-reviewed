from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import (
    effective_request_filtering_section,
    effective_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.request_filtering_allow_double_escaping"
_REQUEST_FILTERING_PATH = "system.webServer/security/requestFiltering"


@rule(
    rule_id=RULE_ID,
    title="Request filtering allows double escaping",
    severity="medium",
    description="Request filtering allows double-encoded URLs.",
    recommendation="Set allowDoubleEscaping to false.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=507,
)
def find_request_filtering_allow_double_escaping(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in _effective_request_filtering_sections(effective_config):
            if section.attributes.get("allowDoubleEscaping", "").lower() == "true":
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID, title="Request filtering allows double escaping", severity="medium",
                    description=(
                        f"IIS request filtering allows double-escaped characters{ctx}. "
                        "This can be exploited to bypass URL-based "
                        "security restrictions and access restricted resources."
                    ),
                    recommendation='Set requestFiltering allowDoubleEscaping="false" or remove the attribute to restore the default restriction.',
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "requestFiltering" and section.attributes.get("allowDoubleEscaping", "").lower() == "true":
                findings.append(Finding(
                    rule_id=RULE_ID, title="Request filtering allows double escaping", severity="medium",
                    description="IIS request filtering is configured to allow double-escaped characters in URLs. This can be exploited to bypass URL-based security restrictions and access restricted resources.",
                    recommendation='Set requestFiltering allowDoubleEscaping="false" or remove the attribute to restore the default restriction.',
                    location=raw_location(section),
                ))

    return findings


def _effective_request_filtering_sections(
    effective_config: IISEffectiveConfig,
) -> list[IISEffectiveSection]:
    sections: list[IISEffectiveSection] = []
    for scope in effective_config.all_sections:
        if scope.section_path != "system.webServer" or is_pure_inheritance(scope):
            continue
        section = _effective_request_filtering_section(
            effective_config,
            location_path=scope.location_path,
        )
        if section is not None:
            sections.append(section)
    return sections


def _effective_request_filtering_section(
    effective_config: IISEffectiveConfig,
    *,
    location_path: str | None,
) -> IISEffectiveSection | None:
    return effective_request_filtering_section(
        effective_config,
        location_path=location_path,
    )
