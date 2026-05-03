from __future__ import annotations

from collections.abc import Iterable

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

FORMS_PROTECTION_RULE_ID = "iis.forms_auth_protection_unsafe"
CREDENTIALS_FORMAT_RULE_ID = "iis.credentials_password_format_clear"
CREDENTIALS_STORED_RULE_ID = "iis.credentials_stored_in_config"
HTTP_ONLY_RULE_ID = "iis.http_cookies_http_only_disabled"
RETAIL_RULE_ID = "iis.deployment_retail_not_enabled"
TRUST_RULE_ID = "iis.trust_level_full"
MACHINE_KEY_RULE_ID = "iis.machine_key_validation_weak"

_FORMS_PATH_SUFFIX = "/system.web/authentication/forms"
_CREDENTIALS_PATH_SUFFIX = "/system.web/authentication/forms/credentials"
_CREDENTIAL_USER_PATH_SUFFIX = "/system.web/authentication/forms/credentials/user"
_SHA2_HMAC_MACHINE_KEY_VALIDATION = frozenset(
    {"hmacsha256", "hmacsha384", "hmacsha512"},
)


@rule(
    rule_id=FORMS_PROTECTION_RULE_ID,
    title="Forms authentication cookie protection is unsafe",
    severity="medium",
    description="ASP.NET forms authentication does not use full cookie protection.",
    recommendation='Set forms protection="All".',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=526,
)
def find_forms_auth_protection_unsafe(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    return [
        _forms_protection_finding(section)
        for section in _sections(doc, effective_config, suffix="/forms", tag="forms")
        if _path_endswith(section, _FORMS_PATH_SUFFIX)
        and _configured_value_is_not(section.attributes.get("protection"), "all")
    ]


@rule(
    rule_id=CREDENTIALS_FORMAT_RULE_ID,
    title="Forms credentials use cleartext password format",
    severity="medium",
    description="ASP.NET forms credentials are configured with cleartext password storage.",
    recommendation='Use a hashed password format and avoid storing credentials in web.config.',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=527,
)
def find_credentials_password_format_clear(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    return [
        _credentials_format_finding(section)
        for section in _sections(
            doc,
            effective_config,
            suffix="/credentials",
            tag="credentials",
        )
        if _path_endswith(section, _CREDENTIALS_PATH_SUFFIX)
        and _is_value(section.attributes.get("passwordFormat"), "clear")
    ]


@rule(
    rule_id=CREDENTIALS_STORED_RULE_ID,
    title="Forms credentials are stored in configuration",
    severity="medium",
    description="ASP.NET forms credentials are stored directly in configuration.",
    recommendation="Move credentials into the application identity provider or a protected secret store.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=528,
)
def find_credentials_stored_in_config(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str | None, str | None, str | None]] = set()
    for section in _credential_user_sections(doc, effective_config):
        key = (
            section.source.file_path,
            section.source.xml_path,
            section.location_path,
        )
        if key in seen:
            continue
        seen.add(key)
        findings.append(_credentials_stored_finding(section))
    return findings


@rule(
    rule_id=HTTP_ONLY_RULE_ID,
    title="ASP.NET cookies are not forced HttpOnly",
    severity="medium",
    description="ASP.NET httpCookies disables HttpOnly cookies.",
    recommendation='Set httpCookies httpOnlyCookies="true".',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=529,
)
def find_http_cookies_http_only_disabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    return [
        _http_only_finding(section)
        for section in _sections(
            doc,
            effective_config,
            suffix="/httpCookies",
            tag="httpCookies",
        )
        if _is_value(section.attributes.get("httpOnlyCookies"), "false")
    ]


@rule(
    rule_id=RETAIL_RULE_ID,
    title="ASP.NET deployment retail mode is not enabled",
    severity="medium",
    description="ASP.NET deployment retail mode is explicitly disabled.",
    recommendation='Set deployment retail="true" for production deployments.',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=530,
)
def find_deployment_retail_not_enabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    return [
        _retail_finding(section)
        for section in _sections(
            doc,
            effective_config,
            suffix="/deployment",
            tag="deployment",
        )
        if _is_value(section.attributes.get("retail"), "false")
    ]


@rule(
    rule_id=TRUST_RULE_ID,
    title="ASP.NET trust level is Full",
    severity="medium",
    description="ASP.NET trust is explicitly set to Full.",
    recommendation='Set trust level to the least-privileged level the application supports.',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=531,
)
def find_trust_level_full(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    return [
        _trust_finding(section)
        for section in _sections(doc, effective_config, suffix="/trust", tag="trust")
        if _is_value(section.attributes.get("level"), "full")
    ]


@rule(
    rule_id=MACHINE_KEY_RULE_ID,
    title="MachineKey validation algorithm is not SHA-2 HMAC",
    severity="medium",
    description="ASP.NET machineKey uses a non-SHA-2 HMAC validation algorithm.",
    recommendation='Use HMACSHA256 or stronger for machineKey validation.',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=532,
)
def find_machine_key_validation_weak(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    return [
        _machine_key_finding(section)
        for section in _sections(
            doc,
            effective_config,
            suffix="/machineKey",
            tag="machineKey",
        )
        if _has_non_sha2_machine_key_validation(section.attributes.get("validation"))
    ]


def _sections(
    doc: IISConfigDocument,
    effective_config: IISEffectiveConfig | None,
    *,
    suffix: str,
    tag: str,
) -> Iterable[IISEffectiveSection | IISSection]:
    if effective_config is not None:
        return (
            section
            for section in effective_config.all_sections
            if section.section_path_suffix == suffix and not is_pure_inheritance(section)
        )
    return (section for section in doc.sections if section.tag == tag)


def _path_endswith(section: IISEffectiveSection | IISSection, suffix: str) -> bool:
    return (section.source.xml_path or "").lower().endswith(suffix)


def _credential_user_sections(
    doc: IISConfigDocument,
    effective_config: IISEffectiveConfig | None,
) -> Iterable[IISEffectiveSection | IISSection]:
    for section in doc.sections:
        if _is_stored_credential_user(section):
            yield section

    if effective_config is None:
        return

    for section in effective_config.all_sections:
        if section.section_path_suffix != "/user":
            continue
        if is_pure_inheritance(section):
            continue
        if _is_stored_credential_user(section):
            yield section


def _configured_value_is_not(value: object, expected: str) -> bool:
    if value is None:
        return False
    return _lower_value(value) != expected


def _is_value(value: object, expected: str) -> bool:
    return _lower_value(value) == expected


def _lower_value(value: object) -> str:
    return str(value).strip().lower()


def _is_stored_credential_user(section: IISEffectiveSection | IISSection) -> bool:
    return (
        _path_endswith(section, _CREDENTIAL_USER_PATH_SUFFIX)
        and section.attributes.get("password", "") != ""
    )


def _has_non_sha2_machine_key_validation(value: object) -> bool:
    if value is None:
        return False
    normalized = _lower_value(value)
    return normalized != "" and normalized not in _SHA2_HMAC_MACHINE_KEY_VALIDATION


def _forms_protection_finding(section: IISEffectiveSection | IISSection) -> Finding:
    protection = section.attributes.get("protection", "")
    ctx = _context(section)
    return Finding(
        rule_id=FORMS_PROTECTION_RULE_ID,
        title="Forms authentication cookie protection is unsafe",
        severity="medium",
        description=(
            f'ASP.NET forms authentication protection is set to "{protection}"{ctx}. '
            "Authentication cookies should be encrypted and validated."
        ),
        recommendation='Set forms protection="All" so forms authentication cookies are encrypted and validated.',
        location=_location(section),
    )


def _credentials_format_finding(
    section: IISEffectiveSection | IISSection,
) -> Finding:
    ctx = _context(section)
    return Finding(
        rule_id=CREDENTIALS_FORMAT_RULE_ID,
        title="Forms credentials use cleartext password format",
        severity="medium",
        description=(
            f"ASP.NET forms credentials use passwordFormat=\"Clear\"{ctx}. "
            "Configuration files can be read from backups, deployments, or "
            "misconfigured file serving paths."
        ),
        recommendation="Do not store reusable credentials in web.config; if legacy forms credentials remain, use a hashed password format.",
        location=_location(section),
    )


def _credentials_stored_finding(
    section: IISEffectiveSection | IISSection,
) -> Finding:
    ctx = _context(section)
    user_name = section.attributes.get("name", "<unnamed>")
    return Finding(
        rule_id=CREDENTIALS_STORED_RULE_ID,
        title="Forms credentials are stored in configuration",
        severity="medium",
        description=(
            f"ASP.NET forms credentials are stored in configuration{ctx} "
            f"(user: {user_name}). Configuration-backed credentials are "
            "hard to rotate and can leak through source control, backups, "
            "or misconfigured file serving paths."
        ),
        recommendation="Move these credentials into the application identity provider or a protected secret store.",
        location=_location(section),
    )


def _http_only_finding(section: IISEffectiveSection | IISSection) -> Finding:
    ctx = _context(section)
    return Finding(
        rule_id=HTTP_ONLY_RULE_ID,
        title="ASP.NET cookies are not forced HttpOnly",
        severity="medium",
        description=(
            f"ASP.NET httpCookies explicitly disables HttpOnly cookies{ctx}. "
            "Client-side script can read cookies that would otherwise be "
            "shielded from common cross-site scripting impact."
        ),
        recommendation='Set httpCookies httpOnlyCookies="true".',
        location=_location(section),
    )


def _retail_finding(section: IISEffectiveSection | IISSection) -> Finding:
    ctx = _context(section)
    return Finding(
        rule_id=RETAIL_RULE_ID,
        title="ASP.NET deployment retail mode is not enabled",
        severity="medium",
        description=(
            f"ASP.NET deployment retail mode is explicitly disabled{ctx}. "
            "Production deployments can expose debug or detailed error behavior "
            "when retail mode is not enforced."
        ),
        recommendation='Set deployment retail="true" in production configuration.',
        location=_location(section),
    )


def _trust_finding(section: IISEffectiveSection | IISSection) -> Finding:
    ctx = _context(section)
    return Finding(
        rule_id=TRUST_RULE_ID,
        title="ASP.NET trust level is Full",
        severity="medium",
        description=(
            f"ASP.NET trust level is explicitly set to Full{ctx}. "
            "Full trust grants the application broad runtime permissions."
        ),
        recommendation="Set trust to the least-privileged level supported by the application.",
        location=_location(section),
    )


def _machine_key_finding(section: IISEffectiveSection | IISSection) -> Finding:
    validation = section.attributes.get("validation", "")
    ctx = _context(section)
    return Finding(
        rule_id=MACHINE_KEY_RULE_ID,
        title="MachineKey validation algorithm is not SHA-2 HMAC",
        severity="medium",
        description=(
            f'ASP.NET machineKey validation uses "{validation}"{ctx}. '
            "CIS IIS hardening recommends SHA-2 HMAC validation for "
            "MachineKey integrity protection."
        ),
        recommendation='Use HMACSHA256 or stronger for machineKey validation.',
        location=_location(section),
    )


def _context(section: IISEffectiveSection | IISSection) -> str:
    if isinstance(section, IISEffectiveSection):
        return location_context(section)
    return ""


def _location(section: IISEffectiveSection | IISSection):
    if isinstance(section, IISEffectiveSection):
        return effective_location(section)
    return raw_location(section)
