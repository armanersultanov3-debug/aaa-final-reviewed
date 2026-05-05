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
REMOVE_SERVER_HEADER_RULE_ID = "iis.request_filtering_remove_server_header_disabled"

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
        findings = [
            _effective_file_extensions_finding(section)
            for section in effective_config.all_sections
            if section.section_path_suffix == "/fileExtensions"
            and _allows_unlisted_by_default(section.attributes.get("allowUnlisted"))
        ]
        findings.extend(
            _effective_file_extensions_missing_finding(section)
            for section in effective_config.all_sections
            if section.section_path_suffix == "/requestFiltering"
            and not is_pure_inheritance(section)
            and not _has_file_extensions_section(effective_config, section.location_path)
        )
        return findings

    findings = [
        _raw_file_extensions_finding(section)
        for section in doc.sections
        if section.tag == "fileExtensions"
        and _allows_unlisted_by_default(section.attributes.get("allowUnlisted"))
    ]
    findings.extend(
        _raw_file_extensions_missing_finding(section)
        for section in doc.sections
        if section.tag == "requestFiltering"
        and not _has_raw_file_extensions_section(doc, section.location_path)
    )
    return findings


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


@rule(
    rule_id=REMOVE_SERVER_HEADER_RULE_ID,
    title="IIS Server header removal is disabled",
    severity="low",
    description="IIS request filtering is configured to return the native Server header.",
    recommendation='Set requestFiltering removeServerHeader to "true".',
    category="local",
    server_type="iis",
    tags=("disclosure",),
    input_kind="effective",
    order=533,
)
def find_request_filtering_remove_server_header_disabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return [
            _effective_remove_server_header_finding(section)
            for section in effective_config.all_sections
            if section.section_path_suffix == "/requestFiltering"
            and not is_pure_inheritance(section)
            and _is_false(section.attributes.get("removeServerHeader"))
        ]
    return [
        _raw_remove_server_header_finding(section)
        for section in doc.sections
        if section.tag == "requestFiltering"
        and _is_false(section.attributes.get("removeServerHeader"))
    ]


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
    normalized = raw_val.strip()
    if normalized == "":
        return None
    if normalized.isdigit() and int(normalized) <= threshold:
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


def _effective_file_extensions_missing_finding(section: IISEffectiveSection) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=FILE_EXTENSIONS_RULE_ID,
        title="Request filtering allows unlisted file extensions",
        severity="medium",
        description=(
            f"IIS request filtering does not define a fileExtensions allowlist{ctx}. "
            "The default policy allows unlisted extensions, so unexpected file "
            "types may reach the application."
        ),
        recommendation='Add fileExtensions allowUnlisted="false" and allow only required file extensions.',
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


def _raw_file_extensions_missing_finding(section: IISSection) -> Finding:
    return Finding(
        rule_id=FILE_EXTENSIONS_RULE_ID,
        title="Request filtering allows unlisted file extensions",
        severity="medium",
        description=(
            "IIS request filtering does not define a fileExtensions allowlist. "
            "The default policy allows unlisted extensions, so unexpected file "
            "types may reach the application."
        ),
        recommendation='Add fileExtensions allowUnlisted="false" and allow only required file extensions.',
        location=raw_location(section),
    )


def _has_file_extensions_section(
    effective_config: IISEffectiveConfig,
    location_path: str | None,
) -> bool:
    return any(
        section.section_path_suffix == "/fileExtensions"
        and section.location_path == location_path
        for section in effective_config.all_sections
    )


def _has_raw_file_extensions_section(
    doc: IISConfigDocument,
    location_path: str | None,
) -> bool:
    candidate_locations = set(_location_inheritance_chain(location_path))
    return any(
        section.tag == "fileExtensions"
        and _normalize_location_path(section.location_path) in candidate_locations
        for section in doc.sections
    )


def _location_inheritance_chain(location_path: str | None) -> list[str | None]:
    normalized = _normalize_location_path(location_path)
    if normalized is None:
        return [None]

    locations: list[str | None] = [normalized]
    parts = normalized.split("/")
    for depth in range(len(parts) - 1, 0, -1):
        locations.append("/".join(parts[:depth]))
    locations.append(None)
    return locations


def _normalize_location_path(location_path: str | None) -> str | None:
    if location_path is None:
        return None
    normalized = location_path.replace("\\", "/").strip("/")
    return normalized or None


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


def _effective_remove_server_header_finding(
    section: IISEffectiveSection,
) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=REMOVE_SERVER_HEADER_RULE_ID,
        title="IIS Server header removal is disabled",
        severity="low",
        description=(
            f"IIS request filtering explicitly disables native Server header "
            f"removal{ctx}. The default IIS Server header can disclose server "
            "technology and version information."
        ),
        recommendation='Set requestFiltering removeServerHeader="true" to suppress the native IIS Server header.',
        location=effective_location(section),
    )


def _raw_remove_server_header_finding(section: IISSection) -> Finding:
    return Finding(
        rule_id=REMOVE_SERVER_HEADER_RULE_ID,
        title="IIS Server header removal is disabled",
        severity="low",
        description=(
            "IIS request filtering explicitly disables native Server header "
            "removal. The default IIS Server header can disclose server "
            "technology and version information."
        ),
        recommendation='Set requestFiltering removeServerHeader="true" to suppress the native IIS Server header.',
        location=raw_location(section),
    )


def _is_true(value: object) -> bool:
    return str(value).strip().lower() == "true"


def _is_false(value: object) -> bool:
    return str(value).strip().lower() == "false"


def _allows_unlisted_by_default(value: object) -> bool:
    return str(value).strip().lower() != "false"
