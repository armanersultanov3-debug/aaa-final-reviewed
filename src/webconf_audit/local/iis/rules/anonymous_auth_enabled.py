from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    _ANONYMOUS_AUTH_SECTION_PATH,
    _AUTHENTICATION_SECTION_PATH,
    _AUTH_RELATED_SECTION_PATHS,
    _OTHER_AUTH_SECTION_PATHS,
    effective_location,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.anonymous_auth_enabled"


@rule(
    rule_id=RULE_ID,
    title="Anonymous authentication enabled alongside other schemes",
    severity="medium",
    description="Anonymous authentication is enabled together with other authentication schemes.",
    recommendation="Disable anonymous authentication if named auth is required.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=519,
)
def find_anonymous_auth_enabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _check_effective(effective_config)
    return _check_raw(doc.sections)


def _check_effective(effective_config: IISEffectiveConfig) -> list[Finding]:
    findings: list[Finding] = []
    for location_path in _effective_auth_candidate_locations(effective_config):
        section = effective_config.get_effective_or_default_section(
            _ANONYMOUS_AUTH_SECTION_PATH,
            location_path=location_path,
            anchor_paths=(
                _AUTHENTICATION_SECTION_PATH,
                "system.webServer/security",
                "system.webServer",
            ),
        )
        if section is None or section.attributes.get("enabled", "").lower() != "true":
            continue

        active_others: list[str] = []
        for auth_path, label in _OTHER_AUTH_SECTION_PATHS:
            other = effective_config.get_effective_or_default_section(
                auth_path,
                location_path=location_path,
                anchor_paths=(
                    _AUTHENTICATION_SECTION_PATH,
                    "system.webServer/security",
                    "system.webServer",
                ),
            )
            if other is not None and other.attributes.get("enabled", "").lower() == "true":
                active_others.append(label)

        if active_others:
            findings.append(_effective_finding(section, active_others))

    return findings


def _check_raw(sections: list[IISSection]) -> list[Finding]:
    findings: list[Finding] = []
    for group in _sections_by_location(sections).values():
        finding = _raw_group_finding(group)
        if finding is not None:
            findings.append(finding)
    return findings


def _sections_by_location(
    sections: list[IISSection],
) -> dict[str | None, list[IISSection]]:
    by_location: dict[str | None, list[IISSection]] = {}
    for section in sections:
        by_location.setdefault(section.location_path, []).append(section)
    return by_location


def _raw_group_finding(group: list[IISSection]) -> Finding | None:
    if not _raw_group_has_auth_context(group):
        return None
    anon_explicit = _raw_section(group, "anonymousAuthentication")
    anon_section = _enabled_raw_section(group, "anonymousAuthentication")
    active_others = _active_raw_auth_schemes(group)
    if not active_others:
        return None
    used_schema_default = False
    if anon_section is None:
        if anon_explicit is not None:
            if anon_explicit.attributes.get("enabled", "").lower() == "false":
                return None
            anon_section = anon_explicit
        else:
            anon_section = _raw_anchor_section(group)
        used_schema_default = True
    if anon_section is None:
        return None

    others_str = ", ".join(active_others)
    default_text = " by default" if used_schema_default else ""
    return Finding(
        rule_id=RULE_ID,
        title="Anonymous authentication enabled alongside other schemes",
        severity="medium",
        description=(
            f"IIS anonymous authentication is enabled{default_text} together with "
            f"{others_str} authentication. This combination can "
            "lead to authorization bypass when anonymous access "
            "satisfies a request before stronger schemes are checked."
        ),
        recommendation=(
            "Disable anonymous authentication where it is not required "
            'by setting anonymousAuthentication enabled="false", or '
            "ensure authorization rules explicitly deny anonymous users."
        ),
        location=raw_location(anon_section),
    )


def _enabled_raw_section(
    sections: list[IISSection],
    tag_name: str,
) -> IISSection | None:
    section = _raw_section(sections, tag_name)
    if section is None:
        return None
    if section.attributes.get("enabled", "").lower() == "true":
        return section
    return None


def _raw_section(
    sections: list[IISSection],
    tag_name: str,
) -> IISSection | None:
    for section in sections:
        if section.tag != tag_name:
            continue
        return section
    return None


def _active_raw_auth_schemes(sections: list[IISSection]) -> list[str]:
    active: list[str] = []
    for tag_name, label in (
        ("basicAuthentication", "basic"),
        ("windowsAuthentication", "Windows"),
        ("digestAuthentication", "digest"),
    ):
        if _enabled_raw_section(sections, tag_name) is not None:
            active.append(label)
    return active


def _effective_auth_candidate_locations(
    effective_config: IISEffectiveConfig,
) -> list[str | None]:
    locations: set[str | None] = set()
    for section in effective_config.all_sections:
        if (section.section_path or "") in _AUTH_RELATED_SECTION_PATHS:
            locations.add(section.location_path)
    return sorted(locations, key=_location_sort_key)


def _raw_group_has_auth_context(group: list[IISSection]) -> bool:
    return any(
        _strip_configuration_path(section.xml_path) in _AUTH_RELATED_SECTION_PATHS
        for section in group
    )


def _raw_anchor_section(group: list[IISSection]) -> IISSection | None:
    for target_path in (
        _AUTHENTICATION_SECTION_PATH,
        "system.webServer/security",
        "system.webServer",
    ):
        for section in group:
            if _strip_configuration_path(section.xml_path) == target_path:
                return section
    return None


def _effective_finding(
    section: IISEffectiveSection,
    active_others: list[str],
) -> Finding:
    ctx = location_context(section)
    others_str = ", ".join(active_others)
    default_text = " by default" if section.materialized_from_defaults else ""
    return Finding(
        rule_id=RULE_ID,
        title="Anonymous authentication enabled alongside other schemes",
        severity="medium",
        description=(
            f"IIS anonymous authentication is enabled{default_text} together with "
            f"{others_str} authentication{ctx}. This combination can lead to "
            "authorization bypass when anonymous access satisfies a request "
            "before stronger schemes are checked."
        ),
        recommendation=(
            "Disable anonymous authentication where it is not required "
            'by setting anonymousAuthentication enabled="false", or '
            "ensure authorization rules explicitly deny anonymous users."
        ),
        location=effective_location(section),
    )


def _location_sort_key(location_path: str | None) -> tuple[int, str]:
    if location_path is None:
        return (0, "")
    return (location_path.count("/"), location_path)


def _strip_configuration_path(xml_path: str) -> str:
    parts = [part for part in xml_path.replace("\\", "/").split("/") if part]
    if parts and parts[0].casefold() == "configuration":
        parts = parts[1:]
    parts = [part for part in parts if not part.casefold().startswith("location[@path=")]
    return "/".join(parts)
