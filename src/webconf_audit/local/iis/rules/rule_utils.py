"""Shared helpers for IIS rules."""

from __future__ import annotations

from dataclasses import replace

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.iis_defaults import load_defaults
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.models import SourceLocation

_MAX_CONTENT_LENGTH_THRESHOLD = 30_000_000  # IIS default (~28.6 MB)

_WEBDAV_MODULES = frozenset({"webdav"})

_DANGEROUS_HANDLERS = frozenset({"cgimodule"})

_EXPOSE_SERVER_HEADERS = ("x-powered-by", "x-aspnetmvc-version")

_OTHER_AUTH_SUFFIXES = (
    ("/basicAuthentication", "basic"),
    ("/windowsAuthentication", "Windows"),
    ("/digestAuthentication", "digest"),
)

_AUTHENTICATION_SECTION_PATH = "system.webServer/security/authentication"
_ANONYMOUS_AUTH_SECTION_PATH = (
    "system.webServer/security/authentication/anonymousAuthentication"
)
_BASIC_AUTH_SECTION_PATH = "system.webServer/security/authentication/basicAuthentication"
_WINDOWS_AUTH_SECTION_PATH = (
    "system.webServer/security/authentication/windowsAuthentication"
)
_DIGEST_AUTH_SECTION_PATH = (
    "system.webServer/security/authentication/digestAuthentication"
)
_OTHER_AUTH_SECTION_PATHS = (
    (_BASIC_AUTH_SECTION_PATH, "basic"),
    (_WINDOWS_AUTH_SECTION_PATH, "Windows"),
    (_DIGEST_AUTH_SECTION_PATH, "digest"),
)
_AUTH_RELATED_SECTION_PATHS = frozenset(
    {
        _AUTHENTICATION_SECTION_PATH,
        _ANONYMOUS_AUTH_SECTION_PATH,
        _BASIC_AUTH_SECTION_PATH,
        _WINDOWS_AUTH_SECTION_PATH,
        _DIGEST_AUTH_SECTION_PATH,
    },
)
_REQUEST_FILTERING_SECTION_PATH = "system.webServer/security/requestFiltering"
_REQUEST_FILTERING_ANCHORS = (
    "system.webServer/security",
    "system.webServer",
)


def effective_location(section: IISEffectiveSection) -> SourceLocation:
    """Build a SourceLocation from an effective section."""
    src = section.source
    return SourceLocation(
        mode="local",
        kind="xml",
        file_path=src.file_path,
        xml_path=src.xml_path,
    )


def raw_location(section: IISSection) -> SourceLocation:
    """Build a SourceLocation from a raw IISSection."""
    return SourceLocation(
        mode="local",
        kind="xml",
        file_path=section.source.file_path,
        xml_path=section.source.xml_path,
    )


def file_location(doc: IISConfigDocument) -> SourceLocation:
    """Build a file-level SourceLocation from a document."""
    return SourceLocation(mode="local", kind="xml", file_path=doc.file_path)


def location_context(section: IISEffectiveSection) -> str:
    """Return human-readable location context suffix."""
    if section.location_path:
        return f' (at location path "{section.location_path}")'
    return ""


def normalize_location_path(location_path: str | None) -> str | None:
    """Normalize an IIS <location> path for inheritance comparisons."""
    if location_path is None:
        return None
    normalized = location_path.replace("\\", "/").strip("/")
    return normalized or None


def location_inheritance_chain(location_path: str | None) -> list[str | None]:
    """Return location path plus parent locations, ending with the root scope."""
    normalized = normalize_location_path(location_path)
    if normalized is None:
        return [None]

    locations: list[str | None] = [normalized]
    parts = normalized.split("/")
    for depth in range(len(parts) - 1, 0, -1):
        locations.append("/".join(parts[:depth]))
    locations.append(None)
    return locations


def location_applies_to_scope(
    candidate_location: str | None,
    scope_location: str | None,
) -> bool:
    """Return True when a candidate location applies to a scoped location."""
    return normalize_location_path(candidate_location) in set(
        location_inheritance_chain(scope_location),
    )


def is_pure_inheritance(section: IISEffectiveSection) -> bool:
    """Return True if this location section purely inherits without override.

    A location-scoped effective section is purely inherited when none of
    its ``origin_chain`` entries come from a ``<location path="...">``
    block.  We detect this by checking whether the XML path contains the
    ``location[@path=`` fragment produced by the IIS parser.

    This is a heuristic tied to the parser's XML-path format.  If the
    path format changes, this check must be updated accordingly.
    """
    if section.location_path is None:
        return False
    return not any(
        origin.xml_path and "location[@path=" in origin.xml_path.lower()
        for origin in section.origin_chain
    )


def effective_request_filtering_section(
    effective_config: IISEffectiveConfig,
    *,
    location_path: str | None,
) -> IISEffectiveSection | None:
    """Return requestFiltering with schema defaults merged when needed."""
    section = effective_config.get_effective_section("/requestFiltering", location_path)
    if section is not None:
        defaults = load_defaults().get_section_defaults(_REQUEST_FILTERING_SECTION_PATH)
        if not defaults:
            return section
        merged = dict(defaults)
        merged.update(section.attributes)
        if merged == section.attributes:
            return section
        return replace(
            section,
            attributes=merged,
            materialized_from_defaults=True,
        )

    return effective_config.get_effective_or_default_section(
        _REQUEST_FILTERING_SECTION_PATH,
        location_path=location_path,
        anchor_paths=_REQUEST_FILTERING_ANCHORS,
    )


def has_https_binding(doc: IISConfigDocument) -> bool:
    """Return True if any parsed section contains an HTTPS binding."""
    for section in doc.sections:
        if section.tag != "bindings":
            continue
        for child in section.children:
            if child.tag.lower() != "binding":
                continue
            protocol = child.attributes.get("protocol", "").lower()
            binding_info = child.attributes.get("bindingInformation", "")
            if protocol == "https" or ":443:" in binding_info:
                return True
    return False


def ssl_flag_tokens(value: object) -> set[str]:
    if value is None:
        return set()
    return {
        token.strip().lower()
        for token in str(value).replace(";", ",").split(",")
        if token.strip()
    }


__all__ = [
    "_ANONYMOUS_AUTH_SECTION_PATH",
    "_AUTHENTICATION_SECTION_PATH",
    "_AUTH_RELATED_SECTION_PATHS",
    "_BASIC_AUTH_SECTION_PATH",
    "_DANGEROUS_HANDLERS",
    "_DIGEST_AUTH_SECTION_PATH",
    "_EXPOSE_SERVER_HEADERS",
    "_MAX_CONTENT_LENGTH_THRESHOLD",
    "_OTHER_AUTH_SECTION_PATHS",
    "_OTHER_AUTH_SUFFIXES",
    "_WEBDAV_MODULES",
    "_WINDOWS_AUTH_SECTION_PATH",
    "effective_request_filtering_section",
    "effective_location",
    "file_location",
    "has_https_binding",
    "is_pure_inheritance",
    "location_applies_to_scope",
    "location_context",
    "location_inheritance_chain",
    "normalize_location_path",
    "raw_location",
    "ssl_flag_tokens",
]
