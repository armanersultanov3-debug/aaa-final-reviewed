from __future__ import annotations

from webconf_audit.local.iis.iis_defaults import load_defaults
from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    is_pure_inheritance,
    location_applies_to_scope,
    location_context,
    location_inheritance_chain,
    normalize_location_path,
    raw_location,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

MAX_URL_RULE_ID = "iis.request_filtering_max_url_too_high"
MAX_QUERY_STRING_RULE_ID = "iis.request_filtering_max_query_string_too_high"
MAX_URL_MISSING_RULE_ID = "iis.request_filtering_max_url_missing"
MAX_QUERY_STRING_MISSING_RULE_ID = "iis.request_filtering_max_query_string_missing"
FILE_EXTENSIONS_RULE_ID = "iis.file_extensions_allow_unlisted"
ISAPI_CGI_RULE_ID = "iis.isapi_cgi_restrictions_allow_unlisted"
REMOVE_SERVER_HEADER_RULE_ID = "iis.request_filtering_remove_server_header_disabled"

_MAX_URL_THRESHOLD = 4096
_MAX_QUERY_STRING_THRESHOLD = 2048
_REQUEST_FILTERING_PATH = "system.webServer/security/requestFiltering"
_REQUEST_LIMITS_PATH = "system.webServer/security/requestFiltering/requestLimits"
_FILE_EXTENSIONS_PATH = "system.webServer/security/requestFiltering/fileExtensions"
_REQUEST_FILTERING_ANCHORS = (
    _REQUEST_FILTERING_PATH,
    "system.webServer/security",
    "system.webServer",
)


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
    rule_id=MAX_URL_MISSING_RULE_ID,
    title="Request filtering maximum URL length is not set",
    severity="low",
    description="Request filtering does not explicitly cap URL length.",
    recommendation='Set requestLimits maxUrl to "4096" or lower.',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=544,
)
def find_request_filtering_max_url_missing(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    return _missing_limit_findings(
        doc,
        effective_config=effective_config,
        attribute="maxUrl",
        rule_id=MAX_URL_MISSING_RULE_ID,
        title="Request filtering maximum URL length is not set",
        unit_label="URL",
        recommendation='Set requestLimits maxUrl to "4096" or lower.',
    )


@rule(
    rule_id=MAX_QUERY_STRING_MISSING_RULE_ID,
    title="Request filtering maximum query string length is not set",
    severity="low",
    description="Request filtering does not explicitly cap query string length.",
    recommendation='Set requestLimits maxQueryString to "2048" or lower.',
    category="local",
    server_type="iis",
    input_kind="effective",
    order=545,
)
def find_request_filtering_max_query_string_missing(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    return _missing_limit_findings(
        doc,
        effective_config=effective_config,
        attribute="maxQueryString",
        rule_id=MAX_QUERY_STRING_MISSING_RULE_ID,
        title="Request filtering maximum query string length is not set",
        unit_label="query string",
        recommendation='Set requestLimits maxQueryString to "2048" or lower.',
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
        findings: list[Finding] = []
        for scope in _effective_request_filtering_scopes(effective_config):
            section = effective_config.get_effective_or_default_section(
                _FILE_EXTENSIONS_PATH,
                location_path=scope.location_path,
                anchor_paths=_REQUEST_FILTERING_ANCHORS,
            )
            if section is None:
                continue
            if _allows_unlisted_by_default(section.attributes.get("allowUnlisted")):
                findings.append(_effective_file_extensions_finding(section))
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
        findings: list[Finding] = []
        for scope in _effective_request_filtering_scopes(effective_config):
            section = effective_config.get_effective_or_default_section(
                _REQUEST_FILTERING_PATH,
                location_path=scope.location_path,
                anchor_paths=("system.webServer/security", "system.webServer"),
            )
            if section is None:
                continue
            if _is_not_true(section.attributes.get("removeServerHeader")):
                findings.append(_effective_remove_server_header_finding(section))
        return findings
    return [
        _raw_remove_server_header_finding(section)
        for section in doc.sections
        if section.tag == "requestFiltering"
        and _is_not_true(
            _raw_request_filtering_attribute(
                doc,
                section.location_path,
                "removeServerHeader",
            ),
        )
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
            for scope in _effective_request_filtering_scopes(effective_config)
            if (
                section := effective_config.get_effective_or_default_section(
                    _REQUEST_LIMITS_PATH,
                    location_path=scope.location_path,
                    anchor_paths=_REQUEST_FILTERING_ANCHORS,
                )
            )
            is not None
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


def _missing_limit_findings(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None,
    attribute: str,
    rule_id: str,
    title: str,
    unit_label: str,
    recommendation: str,
) -> list[Finding]:
    if effective_config is not None:
        findings = [
            _missing_limit_finding_for_section(
                section,
                attribute=attribute,
                rule_id=rule_id,
                title=title,
                unit_label=unit_label,
                recommendation=recommendation,
            )
            for scope in _effective_request_filtering_scopes(effective_config)
            if (
                section := effective_config.get_effective_or_default_section(
                    _REQUEST_LIMITS_PATH,
                    location_path=scope.location_path,
                    anchor_paths=_REQUEST_FILTERING_ANCHORS,
                )
            )
            is not None
            and not str(section.attributes.get(attribute, "")).strip()
        ]
        return findings

    findings = [
        _missing_limit_finding(
            raw_location(section),
            context_suffix="",
            attribute=attribute,
            rule_id=rule_id,
            title=title,
            unit_label=unit_label,
            recommendation=recommendation,
        )
        for section in doc.sections
        if section.tag == "requestLimits"
        and not str(
            _raw_request_limits_attribute(doc, section.location_path, attribute) or "",
        ).strip()
    ]
    return findings


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


def _missing_limit_finding_for_section(
    section: IISEffectiveSection,
    *,
    attribute: str,
    rule_id: str,
    title: str,
    unit_label: str,
    recommendation: str,
) -> Finding:
    return _missing_limit_finding(
        effective_location(section),
        context_suffix=location_context(section),
        attribute=attribute,
        rule_id=rule_id,
        title=title,
        unit_label=unit_label,
        recommendation=recommendation,
    )


def _missing_limit_finding(
    location: SourceLocation,
    *,
    context_suffix: str,
    attribute: str,
    rule_id: str,
    title: str,
    unit_label: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity="low",
        description=(
            f"IIS requestLimits does not set {attribute}{context_suffix}. "
            f"The effective {unit_label} limit is inherited from IIS defaults "
            "or parent configuration rather than being explicitly bounded here."
        ),
        recommendation=recommendation,
        location=location,
    )


def _effective_file_extensions_finding(section: IISEffectiveSection) -> Finding:
    ctx = location_context(section)
    if section.materialized_from_defaults:
        description = (
            f"IIS request filtering allows unlisted file extensions by default{ctx}. "
            "The schema-default policy allows unlisted extensions, so unexpected "
            "file types may reach the application."
        )
        recommendation = (
            'Set fileExtensions allowUnlisted="false" and add only required '
            "file extensions."
        )
        return Finding(
            rule_id=FILE_EXTENSIONS_RULE_ID,
            title="Request filtering allows unlisted file extensions",
            severity="medium",
            description=description,
            recommendation=recommendation,
            location=effective_location(section),
        )
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


def _has_effective_request_limits_section(
    effective_config: IISEffectiveConfig,
    location_path: str | None,
) -> bool:
    return any(
        section.section_path_suffix == "/requestLimits"
        and location_applies_to_scope(section.location_path, location_path)
        for section in effective_config.all_sections
    )


def _has_raw_request_limits_section(
    doc: IISConfigDocument,
    location_path: str | None,
) -> bool:
    return any(
        section.tag == "requestLimits"
        and location_applies_to_scope(section.location_path, location_path)
        for section in doc.sections
    )


def _raw_request_filtering_attribute(
    doc: IISConfigDocument,
    location_path: str | None,
    attribute: str,
) -> str | None:
    for location in location_inheritance_chain(location_path):
        for section in reversed(doc.sections):
            if section.tag != "requestFiltering":
                continue
            if normalize_location_path(section.location_path) != location:
                continue
            if attribute in section.attributes:
                return section.attributes.get(attribute)
    return load_defaults().get_section_attribute_default(
        _REQUEST_FILTERING_PATH,
        attribute,
    )


def _raw_request_limits_attribute(
    doc: IISConfigDocument,
    location_path: str | None,
    attribute: str,
) -> str | None:
    for location in location_inheritance_chain(location_path):
        for section in reversed(doc.sections):
            if section.tag != "requestLimits":
                continue
            if normalize_location_path(section.location_path) != location:
                continue
            if attribute in section.attributes:
                return section.attributes.get(attribute)
    return load_defaults().get_element_default(_REQUEST_LIMITS_PATH).get(attribute)


def _has_raw_file_extensions_section(
    doc: IISConfigDocument,
    location_path: str | None,
) -> bool:
    candidate_locations = set(location_inheritance_chain(location_path))
    return any(
        section.tag == "fileExtensions"
        and normalize_location_path(section.location_path) in candidate_locations
        for section in doc.sections
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


def _effective_remove_server_header_finding(
    section: IISEffectiveSection,
) -> Finding:
    ctx = location_context(section)
    if section.materialized_from_defaults:
        description = (
            f"IIS request filtering leaves native Server header removal disabled "
            f"by default{ctx}. The default IIS Server header can disclose server "
            "technology and version information."
        )
    else:
        description = (
            f"IIS request filtering explicitly disables native Server header "
            f"removal{ctx}. The default IIS Server header can disclose server "
            "technology and version information."
        )
    return Finding(
        rule_id=REMOVE_SERVER_HEADER_RULE_ID,
        title="IIS Server header removal is disabled",
        severity="low",
        description=description,
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


def _is_not_true(value: object) -> bool:
    return str(value).strip().lower() != "true"


def _allows_unlisted_by_default(value: object) -> bool:
    return str(value).strip().lower() != "false"


def _effective_request_filtering_scopes(
    effective_config: IISEffectiveConfig,
) -> list[IISEffectiveSection]:
    return [
        section
        for section in effective_config.all_sections
        if section.section_path == "system.webServer"
        and not is_pure_inheritance(section)
    ]
