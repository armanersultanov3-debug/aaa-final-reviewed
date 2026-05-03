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
from webconf_audit.rule_registry import StandardReference, rule

RULE_ID = "iis.handler_write_script_execute_enabled"

_ACCESS_POLICY_BITS = {
    "write": 2,
    "execute": 4,
    "script": 512,
}


@rule(
    rule_id=RULE_ID,
    title="Handler permissions grant Write with Script or Execute",
    severity="medium",
    description="IIS handler permissions allow write access together with script or executable execution.",
    recommendation=(
        'Remove "Write" from handlers accessPolicy when "Script" or '
        '"Execute" is enabled, or split writable content into a non-executable '
        "path."
    ),
    category="local",
    server_type="iis",
    input_kind="effective",
    standards=(
        StandardReference(
            standard="CIS",
            reference="Microsoft IIS 10 v1.2.1 section 4.8",
            url="https://www.cisecurity.org/benchmark/microsoft_iis",
            coverage="direct",
            note=(
                "Detects handlers accessPolicy values that grant Write "
                "together with Script or Execute."
            ),
        ),
    ),
    order=541,
)
def find_handler_write_script_execute_enabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return [
            _effective_finding(section)
            for section in effective_config.all_sections
            if section.section_path_suffix == "/handlers"
            and not is_pure_inheritance(section)
            and _allows_write_with_script_or_execute(
                section.attributes.get("accessPolicy"),
            )
        ]
    return [
        _raw_finding(section)
        for section in doc.sections
        if section.tag == "handlers"
        and _allows_write_with_script_or_execute(
            section.attributes.get("accessPolicy"),
        )
    ]


def _allows_write_with_script_or_execute(value: object) -> bool:
    flags = _access_policy_flags(value)
    return "write" in flags and bool(flags & {"script", "execute"})


def _access_policy_flags(value: object) -> set[str]:
    if value is None:
        return set()
    raw = str(value).strip()
    if not raw:
        return set()
    if raw.isdigit():
        return _numeric_access_policy_flags(int(raw))
    normalized = raw
    for separator in (";", "|", " "):
        normalized = normalized.replace(separator, ",")
    return {
        token.strip().lower()
        for token in normalized.split(",")
        if token.strip()
    }


def _numeric_access_policy_flags(mask: int) -> set[str]:
    return {
        name
        for name, bit in _ACCESS_POLICY_BITS.items()
        if mask & bit
    }


def _effective_finding(section: IISEffectiveSection) -> Finding:
    access_policy = section.attributes.get("accessPolicy", "")
    ctx = location_context(section)
    return Finding(
        rule_id=RULE_ID,
        title="Handler permissions grant Write with Script or Execute",
        severity="medium",
        description=(
            f'IIS handlers accessPolicy is "{access_policy}"{ctx}. '
            "Granting Write together with Script or Execute lets writable "
            "content paths become code-execution paths."
        ),
        recommendation=(
            'Remove "Write" from handlers accessPolicy where "Script" or '
            '"Execute" is enabled, or place writable content under a separate '
            "non-executable location."
        ),
        location=effective_location(section),
        metadata={"access_policy": access_policy},
    )


def _raw_finding(section: IISSection) -> Finding:
    access_policy = section.attributes.get("accessPolicy", "")
    return Finding(
        rule_id=RULE_ID,
        title="Handler permissions grant Write with Script or Execute",
        severity="medium",
        description=(
            f'IIS handlers accessPolicy is "{access_policy}". '
            "Granting Write together with Script or Execute lets writable "
            "content paths become code-execution paths."
        ),
        recommendation=(
            'Remove "Write" from handlers accessPolicy where "Script" or '
            '"Execute" is enabled, or place writable content under a separate '
            "non-executable location."
        ),
        location=raw_location(section),
        metadata={"access_policy": access_policy},
    )
