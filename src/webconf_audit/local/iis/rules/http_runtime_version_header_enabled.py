from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.effective import IISEffectiveSection
from webconf_audit.local.iis.parser import IISSection
from webconf_audit.local.iis.rules.rule_utils import effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.http_runtime_version_header_enabled"


@rule(
    rule_id=RULE_ID,
    title="ASP.NET version header enabled",
    severity="low",
    description="The ASP.NET version header is enabled.",
    recommendation="Set enableVersionHeader to false.",
    category="local",
    server_type="iis",
    tags=("disclosure",),
    input_kind="effective",
    order=506,
)
def find_http_runtime_version_header_enabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        http_runtime_locations: set[str | None] = set()
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/httpRuntime":
                continue
            http_runtime_locations.add(section.location_path)
            if is_pure_inheritance(section):
                continue
            if section.attributes.get("enableVersionHeader", "").lower() != "false":
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID, title="ASP.NET version header enabled", severity="low",
                    description=(
                        f"The ASP.NET version header (X-AspNet-Version) is explicitly "
                        f"enabled{ctx}. This discloses the ASP.NET framework version to "
                        "external clients and aids fingerprinting."
                    ),
                    recommendation='Set httpRuntime enableVersionHeader="false" to suppress the X-AspNet-Version response header.',
                    location=effective_location(section),
                ))
        for section in _effective_system_web_sections(effective_config):
            if section.location_path in http_runtime_locations:
                continue
            if is_pure_inheritance(section):
                continue
            ctx = location_context(section)
            findings.append(Finding(
                rule_id=RULE_ID,
                title="ASP.NET version header enabled",
                severity="low",
                description=(
                    f"The ASP.NET httpRuntime section is absent{ctx}, so "
                    "enableVersionHeader is not explicitly disabled. ASP.NET "
                    "can emit the X-AspNet-Version response header by default."
                ),
                recommendation='Add httpRuntime enableVersionHeader="false" to suppress the X-AspNet-Version response header.',
                location=effective_location(section),
            ))
    else:
        http_runtime_locations: set[str | None] = set()
        for section in doc.sections:
            if section.tag != "httpRuntime":
                continue
            http_runtime_locations.add(section.location_path)
            if section.attributes.get("enableVersionHeader", "").lower() != "false":
                findings.append(Finding(
                    rule_id=RULE_ID, title="ASP.NET version header enabled", severity="low",
                    description="The ASP.NET version header (X-AspNet-Version) is explicitly enabled. This discloses the ASP.NET framework version to external clients and aids fingerprinting.",
                    recommendation='Set httpRuntime enableVersionHeader="false" to suppress the X-AspNet-Version response header.',
                    location=raw_location(section),
                ))
        for section in _raw_system_web_sections(doc):
            if section.location_path in http_runtime_locations:
                continue
            findings.append(Finding(
                rule_id=RULE_ID,
                title="ASP.NET version header enabled",
                severity="low",
                description=(
                    "The ASP.NET httpRuntime section is absent, so "
                    "enableVersionHeader is not explicitly disabled. ASP.NET "
                    "can emit the X-AspNet-Version response header by default."
                ),
                recommendation='Add httpRuntime enableVersionHeader="false" to suppress the X-AspNet-Version response header.',
                location=raw_location(section),
            ))

    return findings


def _effective_system_web_sections(
    effective_config: IISEffectiveConfig,
) -> list[IISEffectiveSection]:
    return [
        section
        for section in effective_config.all_sections
        if section.section_path_suffix == "/system.web"
    ]


def _raw_system_web_sections(doc: IISConfigDocument) -> list[IISSection]:
    return [section for section in doc.sections if section.tag == "system.web"]
