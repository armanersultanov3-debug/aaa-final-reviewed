from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

MAX_URL_RULE_ID = "iis.request_filtering_max_url_too_high"
MAX_QUERY_STRING_RULE_ID = "iis.request_filtering_max_query_string_too_high"
FILE_EXTENSIONS_RULE_ID = "iis.file_extensions_allow_unlisted"
ISAPI_CGI_RULE_ID = "iis.isapi_cgi_restrictions_allow_unlisted"

_MAX_URL_THRESHOLD = 4096
_MAX_QUERY_STRING_THRESHOLD = 2048


@rule(
    rule_id=MAX_URL_RULE_ID,
    title="Request filtering maximum URL length is unsafe",
    severity="low",
    description="Request filtering allows URLs longer than the CIS IIS benchmark limit.",
    recommendation='Set requestLimits maxUrl to "4096" or lower.',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=522,
)
def find_request_filtering_max_url_too_high(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    return _limit_findings(
        doc,
        effective_config=effective_config,
        attribute="maxUrl",
        threshold=_MAX_URL_THRESHOLD,
        rule_id=MAX_URL_RULE_ID,
        title="Request filtering maximum URL length is unsafe",
        unit_label="URL",
    )


@rule(
    rule_id=MAX_QUERY_STRING_RULE_ID,
    title="Request filtering maximum query string length is unsafe",
    severity="low",
    description="Request filtering allows query strings longer than the CIS IIS benchmark limit.",
    recommendation='Set requestLimits maxQueryString to "2048" or lower.',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=523,
)
def find_request_filtering_max_query_string_too_high(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    return _limit_findings(
        doc,
        effective_config=effective_config,
        attribute="maxQueryString",
        threshold=_MAX_QUERY_STRING_THRESHOLD,
        rule_id=MAX_QUERY_STRING_RULE_ID,
        title="Request filtering maximum query string length is unsafe",
        unit_label="query string",
    )


@rule(
    rule_id=FILE_EXTENSIONS_RULE_ID,
    title="Request filtering allows unlisted file extensions",
    severity="medium",
    description="IIS request filtering allows file extensions that are not explicitly listed.",
    recommendation='Set fileExtensions allowUnlisted to "false" and allow only required extensions.',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=524,
)
def find_file_extensions_allow_unlisted(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return [
            _effective_file_extensions_finding(section)
            for section in effective_config.all_sections
            if section.section_path_suffix == "/fileExtensions"
            and not is_pure_inheritance(section)
            and _is_true(section.attributes.get("allowUnlisted"))
        ]
    return [
        _raw_file_extensions_finding(section)
        for section in doc.sections
        if section.tag == "fileExtensions"
        and _is_true(section.attributes.get("allowUnlisted"))
    ]


@rule(
    rule_id=ISAPI_CGI_RULE_ID,
    title="ISAPI or CGI restrictions allow unlisted executables",
    severity="medium",
    description="IIS allows unlisted ISAPI or CGI executables.",
    recommendation='Set notListedIsapisAllowed and notListedCgisAllowed to "false".',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=525,
)
def find_isapi_cgi_restrictions_allow_unlisted(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        findings: list[Finding] = []
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/isapiCgiRestriction":
                continue
            if is_pure_inheritance(section):
                continue
            unsafe_attrs = _unsafe_isapi_cgi_attrs(section.attributes)
            if unsafe_attrs:
                findings.append(_effective_isapi_cgi_finding(section, unsafe_attrs))
        return findings

    findings: list[Finding] = []
    for section in doc.sections:
        if section.tag != "isapiCgiRestriction":
            continue
        unsafe_attrs = _unsafe_isapi_cgi_attrs(section.attributes)
        if unsafe_attrs:
            findings.append(_raw_isapi_cgi_finding(section, unsafe_attrs))
    return findings


def _limit_findings(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None,
    attribute: str,
    threshold: int,
    rule_id: str,
    title: str,
    unit_label: str,
) -> list[Finding]:
    if effective_config is not None:
        findings = [
            _limit_finding(
                raw_val=section.attributes.get(attribute, ""),
                location=effective_location(section),
                context_suffix=location_context(section),
                attribute=attribute,
                threshold=threshold,
                rule_id=rule_id,
                title=title,
                unit_label=unit_label,
            )
            for section in effective_config.all_sections
            if section.section_path_suffix == "/requestLimits"
            and not is_pure_inheritance(section)
        ]
    else:
        findings = [
            _limit_finding(
                raw_val=section.attributes.get(attribute, ""),
                location=raw_location(section),
                context_suffix="",
                attribute=attribute,
                threshold=threshold,
                rule_id=rule_id,
                title=title,
                unit_label=unit_label,
            )
            for section in doc.sections
            if section.tag == "requestLimits"
        ]
    return [finding for finding in findings if finding is not None]


def _limit_finding(
    *,
    raw_val: str,
    location: SourceLocation,
    context_suffix: str,
    attribute: str,
    threshold: int,
    rule_id: str,
    title: str,
    unit_label: str,
) -> Finding | None:
    if raw_val == "":
        return None
    if raw_val.isdigit() and int(raw_val) <= threshold:
        return None
    return Finding(
        rule_id=rule_id,
        title=title,
        severity="low",
        description=(
            f"IIS requestLimits {attribute} is set to {raw_val!r}{context_suffix}. "
            f"The CIS IIS benchmark recommends limiting the {unit_label} "
            f"length to {threshold} characters or fewer."
        ),
        recommendation=f'Set requestLimits {attribute} to "{threshold}" or lower.',
        location=location,
    )


def _effective_file_extensions_finding(section: IISEffectiveSection) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=FILE_EXTENSIONS_RULE_ID,
        title="Request filtering allows unlisted file extensions",
        severity="medium",
        description=(
            f"IIS file extension filtering allows unlisted extensions{ctx}. "
            "Requests for unexpected file types may reach the application "
            "instead of being rejected by request filtering."
        ),
        recommendation='Set fileExtensions allowUnlisted="false" and add only required file extensions.',
        location=effective_location(section),
    )


def _raw_file_extensions_finding(section: IISSection) -> Finding:
    return Finding(
        rule_id=FILE_EXTENSIONS_RULE_ID,
        title="Request filtering allows unlisted file extensions",
        severity="medium",
        description=(
            "IIS file extension filtering allows unlisted extensions. "
            "Requests for unexpected file types may reach the application "
            "instead of being rejected by request filtering."
        ),
        recommendation='Set fileExtensions allowUnlisted="false" and add only required file extensions.',
        location=raw_location(section),
    )


def _unsafe_isapi_cgi_attrs(attributes: dict[str, str]) -> list[str]:
    unsafe: list[str] = []
    for name in ("notListedIsapisAllowed", "notListedCgisAllowed"):
        if _is_true(attributes.get(name)):
            unsafe.append(name)
    return unsafe


def _effective_isapi_cgi_finding(
    section: IISEffectiveSection,
    unsafe_attrs: list[str],
) -> Finding:
    ctx = location_context(section)
    attrs = ", ".join(unsafe_attrs)
    return Finding(
        rule_id=ISAPI_CGI_RULE_ID,
        title="ISAPI or CGI restrictions allow unlisted executables",
        severity="medium",
        description=(
            f"IIS allows unlisted ISAPI or CGI executables{ctx} "
            f"({attrs}). Unlisted executable handlers can expand the "
            "server-side code execution surface."
        ),
        recommendation='Set notListedIsapisAllowed="false" and notListedCgisAllowed="false".',
        location=effective_location(section),
    )


def _raw_isapi_cgi_finding(
    section: IISSection,
    unsafe_attrs: list[str],
) -> Finding:
    attrs = ", ".join(unsafe_attrs)
    return Finding(
        rule_id=ISAPI_CGI_RULE_ID,
        title="ISAPI or CGI restrictions allow unlisted executables",
        severity="medium",
        description=(
            f"IIS allows unlisted ISAPI or CGI executables ({attrs}). "
            "Unlisted executable handlers can expand the server-side code "
            "execution surface."
        ),
        recommendation='Set notListedIsapisAllowed="false" and notListedCgisAllowed="false".',
        location=raw_location(section),
    )


def _is_true(value: object) -> bool:
    return str(value).strip().lower() == "true"

