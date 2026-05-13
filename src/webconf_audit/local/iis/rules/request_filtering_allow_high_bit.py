from __future__ import annotations

from webconf_audit.local.iis.iis_defaults import load_defaults
from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.request_filtering_allow_high_bit"
_REQUEST_FILTERING_PATH = "system.webServer/security/requestFiltering"


@rule(
    rule_id=RULE_ID,
    title="Request filtering allows high-bit characters",
    severity="low",
    description="Request filtering allows high-bit characters in URLs.",
    recommendation="Set allowHighBitCharacters to false unless required.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=508,
)
def find_request_filtering_allow_high_bit(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in _effective_request_filtering_sections(effective_config):
            if section.attributes.get("allowHighBitCharacters", "").lower() != "false":
                ctx = location_context(section)
                default_text = " by default" if section.materialized_from_defaults else ""
                findings.append(Finding(
                    rule_id=RULE_ID, title="Request filtering allows high-bit characters", severity="low",
                    description=(
                        f"IIS request filtering allows high-bit (non-ASCII) characters "
                        f"in URLs{default_text}{ctx}. This can facilitate homograph attacks and "
                        "may bypass URL-based security filters."
                    ),
                    recommendation='Set requestFiltering allowHighBitCharacters="false" unless non-ASCII URLs are explicitly required.',
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "requestFiltering" and section.attributes.get("allowHighBitCharacters", "").lower() != "false":
                findings.append(Finding(
                    rule_id=RULE_ID, title="Request filtering allows high-bit characters", severity="low",
                    description="IIS request filtering allows high-bit (non-ASCII) characters in URLs. This can facilitate homograph attacks and may bypass URL-based security filters.",
                    recommendation='Set requestFiltering allowHighBitCharacters="false" unless non-ASCII URLs are explicitly required.',
                    location=raw_location(section),
                ))

    return findings


def _effective_request_filtering_sections(
    effective_config: IISEffectiveConfig,
) -> list:
    sections = []
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
):
    section = effective_config.get_effective_section("/requestFiltering", location_path)
    if section is not None:
        defaults = load_defaults().get_section_defaults(_REQUEST_FILTERING_PATH)
        merged = dict(defaults)
        merged.update(section.attributes)
        if merged == section.attributes:
            return section
        return type(section)(
            tag=section.tag,
            section_path_suffix=section.section_path_suffix,
            attributes=merged,
            children=list(section.children),
            location_path=section.location_path,
            origin_chain=list(section.origin_chain),
            child_operations=list(section.child_operations),
            section_path=section.section_path,
            materialized_from_defaults=True,
        )
    return effective_config.get_effective_or_default_section(
        _REQUEST_FILTERING_PATH,
        location_path=location_path,
        anchor_paths=("system.webServer/security", "system.webServer"),
    )
