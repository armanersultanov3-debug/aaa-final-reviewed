"""IIS config to NormalizedConfig mapper.

The normalizer extracts XML-backed signals from ``web.config`` /
``applicationHost.config``. When SChannel registry data is supplied by the IIS
analyzer, it also enriches the global TLS scope with protocol and cipher data.
"""

from __future__ import annotations

import logging

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSourceRef
from webconf_audit.local.iis.registry import IISRegistryTLS
from webconf_audit.local.normalized import (
    NormalizedAccessPolicy,
    NormalizedConfig,
    NormalizedListenPoint,
    NormalizedScope,
    NormalizedSecurityHeader,
    NormalizedTLS,
    SourceRef,
)

_SECURITY_HEADERS = frozenset({
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
})

# Section path suffixes used during extraction.
_ACCESS_SUFFIX = "/access"
_CUSTOM_HEADERS_SUFFIX = "/customHeaders"
_DIR_BROWSE_SUFFIX = "/directoryBrowse"
_HTTP_ERRORS_SUFFIX = "/httpErrors"
_COMPILATION_SUFFIX = "/compilation"
_HTTP_RUNTIME_SUFFIX = "/httpRuntime"

_logger = logging.getLogger(__name__)


def normalize_iis(
    doc: IISConfigDocument,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISRegistryTLS | None = None,
) -> NormalizedConfig:
    """Extract normalized entities from IIS config."""
    if effective_config is None:
        _logger.debug(
            "IIS normalizer: effective_config is None for %s, "
            "returning empty NormalizedConfig",
            doc.file_path,
        )
        return NormalizedConfig(
            server_type="iis",
            auth_requiring_locations=(),
        )

    scopes: list[NormalizedScope] = []

    global_scope = _build_scope(
        effective_config.global_sections,
        scope_name="global",
        doc=doc,
        registry_tls=registry_tls,
    )
    scopes.append(global_scope)

    for loc_path, sections in effective_config.location_sections.items():
        scopes.append(_build_scope(sections, scope_name=loc_path, doc=doc))

    return NormalizedConfig(
        server_type="iis",
        scopes=scopes,
        auth_requiring_locations=(),
    )


def _build_scope(
    sections: dict[str, IISEffectiveSection],
    scope_name: str | None,
    doc: IISConfigDocument,
    registry_tls: IISRegistryTLS | None = None,
) -> NormalizedScope:
    listen_points = _extract_listen_points(doc)
    tls = _extract_tls(sections, registry_tls=registry_tls)
    headers = _extract_security_headers(sections)
    access_policy = _extract_access_policy(sections)

    return NormalizedScope(
        scope_name=scope_name,
        listen_points=listen_points,
        tls=tls,
        security_headers=headers,
        access_policy=access_policy,
    )


def _extract_listen_points(doc: IISConfigDocument) -> list[NormalizedListenPoint]:
    """Extract listen points from IIS bindings if available.

    Bindings are typically in ``system.applicationHost/sites`` inside
    ``applicationHost.config``. For ``web.config`` there are usually no
    bindings, so the result is empty.
    """
    points: list[NormalizedListenPoint] = []
    for section in doc.sections:
        if section.tag != "site":
            continue
        for child in section.children:
            if child.tag != "binding":
                continue
            info = child.attributes.get("bindingInformation", "")
            protocol = child.attributes.get("protocol", "http").lower()
            lp = _parse_binding(info, protocol, child.source)
            if lp is not None:
                points.append(lp)
    return points


def _parse_binding(
    info: str,
    protocol: str,
    source: IISSourceRef,
) -> NormalizedListenPoint | None:
    """Parse ``*:443:hostname`` binding info."""
    parts = info.split(":")
    if len(parts) < 2:
        return None

    address = parts[0] if parts[0] != "*" else None
    try:
        port = int(parts[1])
    except ValueError:
        return None

    is_https = protocol == "https"
    return NormalizedListenPoint(
        port=port,
        protocol=protocol,
        tls=is_https,
        source=_ref(source),
        address=address,
    )


def _extract_tls(
    sections: dict[str, IISEffectiveSection],
    *,
    registry_tls: IISRegistryTLS | None = None,
) -> NormalizedTLS | None:
    access = sections.get(_ACCESS_SUFFIX)
    require_ssl: bool | None = None
    xml_source: SourceRef | None = None

    if access is not None:
        ssl_flags = access.attributes.get("sslFlags", "").lower()
        if ssl_flags:
            require_ssl = "ssl" in ssl_flags
            xml_source = _ref(access.source, details=_registry_details(registry_tls))

    if registry_tls is not None and registry_tls.has_data:
        return NormalizedTLS(
            source=xml_source or registry_tls.source_ref(),
            protocols=registry_tls.protocols_enabled,
            ciphers=_registry_cipher_string(registry_tls),
            require_ssl=require_ssl,
        )

    if xml_source is None:
        return None

    return NormalizedTLS(
        source=xml_source,
        protocols=None,
        ciphers=None,
        require_ssl=require_ssl,
    )


def _extract_security_headers(
    sections: dict[str, IISEffectiveSection],
) -> list[NormalizedSecurityHeader]:
    custom = sections.get(_CUSTOM_HEADERS_SUFFIX)
    if custom is None:
        return []

    headers: list[NormalizedSecurityHeader] = []
    for child in custom.children:
        if child.tag != "add":
            continue
        name = child.attributes.get("name", "").lower()
        if name in _SECURITY_HEADERS:
            value = child.attributes.get("value")
            headers.append(
                NormalizedSecurityHeader(
                    name=name,
                    value=value,
                    source=_ref(child.source),
                )
            )
    return headers


def _extract_access_policy(
    sections: dict[str, IISEffectiveSection],
) -> NormalizedAccessPolicy | None:
    dir_browse = sections.get(_DIR_BROWSE_SUFFIX)
    compilation = sections.get(_COMPILATION_SUFFIX)
    http_runtime = sections.get(_HTTP_RUNTIME_SUFFIX)

    dir_listing = _boolean_attribute(dir_browse, "enabled")
    debug = _boolean_attribute(compilation, "debug")
    disclosed = _version_header_disclosure(http_runtime)

    if dir_listing is None and debug is None and disclosed is None:
        return None

    anchor = dir_browse or compilation or http_runtime
    if anchor is None:
        return None
    return NormalizedAccessPolicy(
        source=_ref(anchor.source),
        directory_listing=dir_listing,
        server_identification_disclosed=disclosed,
        debug_mode=debug,
    )


def _boolean_attribute(
    section: IISEffectiveSection | None,
    attribute_name: str,
) -> bool | None:
    if section is None:
        return None
    return section.attributes.get(attribute_name, "").strip().lower() == "true"


def _version_header_disclosure(
    section: IISEffectiveSection | None,
) -> bool | None:
    if section is None:
        return None

    value = section.attributes.get("enableVersionHeader", "").strip().lower()
    if not value:
        return None
    return value == "true"


def _registry_cipher_string(registry_tls: IISRegistryTLS) -> str | None:
    if registry_tls.ciphers_enabled is None:
        return None
    return ", ".join(registry_tls.ciphers_enabled)


def _registry_details(registry_tls: IISRegistryTLS | None) -> str | None:
    if registry_tls is None or not registry_tls.has_data:
        return None
    return registry_tls.source_details


def _ref(source: IISSourceRef, *, details: str | None = None) -> SourceRef:
    return SourceRef(
        server_type="iis",
        file_path=source.file_path or "",
        line=source.line,
        xml_path=source.xml_path,
        details=details,
    )


__all__ = ["normalize_iis"]
