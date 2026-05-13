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
    AuthRequiringLocation,
    NormalizedAccessPolicy,
    NormalizedConfig,
    NormalizedListenPoint,
    NormalizedScope,
    NormalizedSecurityHeader,
    NormalizedTLS,
    SourceLocation,
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
_AUTHENTICATION_SUFFIX = "/authentication"
_AUTHORIZATION_SUFFIX = "/authorization"
_BASIC_AUTH_SUFFIX = "/basicAuthentication"
_CUSTOM_HEADERS_SUFFIX = "/customHeaders"
_DIR_BROWSE_SUFFIX = "/directoryBrowse"
_FORMS_SUFFIX = "/forms"
_HTTP_ERRORS_SUFFIX = "/httpErrors"
_COMPILATION_SUFFIX = "/compilation"
_HTTP_RUNTIME_SUFFIX = "/httpRuntime"
_WINDOWS_AUTH_SUFFIX = "/windowsAuthentication"

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
    scope_listen_points = _extract_scope_listen_points(doc)
    auth_listen_points = _extract_auth_listen_points(doc, effective_config)

    global_scope = _build_scope(
        effective_config.global_sections,
        scope_name="global",
        doc=doc,
        registry_tls=registry_tls,
        listen_points=scope_listen_points,
    )
    scopes.append(global_scope)

    for loc_path, sections in effective_config.location_sections.items():
        scopes.append(
            _build_scope(
                sections,
                scope_name=loc_path,
                doc=doc,
                listen_points=scope_listen_points,
            )
        )

    return NormalizedConfig(
        server_type="iis",
        scopes=scopes,
        auth_requiring_locations=_extract_auth_requiring_locations(
            effective_config,
            listen_points=auth_listen_points,
        ),
    )


def _build_scope(
    sections: dict[str, IISEffectiveSection],
    scope_name: str | None,
    doc: IISConfigDocument,
    *,
    registry_tls: IISRegistryTLS | None = None,
    listen_points: list[NormalizedListenPoint],
) -> NormalizedScope:
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


def _extract_scope_listen_points(
    doc: IISConfigDocument,
) -> list[NormalizedListenPoint]:
    """Extract scope listen points from explicit ``site`` sections.

    This preserves the historical IIS normalizer behavior for generic
    universal listener/header rules, which operate on hand-built site
    sections in tests rather than parsed ``bindings`` sections.
    """
    points: list[NormalizedListenPoint] = []
    for section in doc.sections:
        if section.tag != "site":
            continue
        for child in section.children:
            if child.tag != "binding":
                continue
            lp = _binding_to_listen_point(child.attributes, child.source)
            if lp is not None:
                points.append(lp)
    return points


def _extract_auth_listen_points(
    doc: IISConfigDocument,
    effective_config: IISEffectiveConfig,
) -> list[NormalizedListenPoint]:
    """Extract listen points from IIS bindings if available.

    Bindings are typically in ``system.applicationHost/sites`` inside
    ``applicationHost.config``. For ``web.config`` there are usually no
    bindings, so the result is empty. When the input document is a site
    ``web.config`` merged with applicationHost-derived effective config,
    fall back to the effective ``/bindings`` section.
    """
    points = _doc_listen_points(doc)
    if points:
        return points

    bindings = effective_config.global_sections.get("/bindings")
    if bindings is None:
        return []

    for child in bindings.children:
        if child.tag != "binding":
            continue
        lp = _binding_to_listen_point(child.attributes, child.source)
        if lp is not None:
            points.append(lp)
    return points


def _doc_listen_points(doc: IISConfigDocument) -> list[NormalizedListenPoint]:
    points: list[NormalizedListenPoint] = []
    for section in doc.sections:
        if section.tag not in {"site", "bindings"}:
            continue
        for child in section.children:
            if child.tag != "binding":
                continue
            lp = _binding_to_listen_point(child.attributes, child.source)
            if lp is not None:
                points.append(lp)
    return points


def _binding_to_listen_point(
    attributes: dict[str, str],
    source: IISSourceRef,
) -> NormalizedListenPoint | None:
    info = attributes.get("bindingInformation", "")
    protocol = attributes.get("protocol", "http").lower()
    return _parse_binding(info, protocol, source)


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


def _extract_auth_requiring_locations(
    effective_config: IISEffectiveConfig,
    *,
    listen_points: list[NormalizedListenPoint],
) -> tuple[AuthRequiringLocation, ...]:
    locations: list[AuthRequiringLocation] = []
    locations.extend(
        _auth_locations_for_scope(
            effective_config.global_sections,
            listen_points=listen_points,
        )
    )
    for location_path, sections in effective_config.location_sections.items():
        locations.extend(
            _auth_locations_for_scope(
                sections,
                location_path=location_path,
                listen_points=listen_points,
            )
        )
    return tuple(locations)


def _auth_locations_for_scope(
    sections: dict[str, IISEffectiveSection],
    *,
    location_path: str | None = None,
    listen_points: list[NormalizedListenPoint],
) -> list[AuthRequiringLocation]:
    locations: list[AuthRequiringLocation] = []
    access = sections.get(_ACCESS_SUFFIX)
    requires_tls = _scope_requires_tls(listen_points, access)
    path = _location_path(location_path)

    basic = sections.get(_BASIC_AUTH_SUFFIX)
    if _enabled_auth_section(basic) and not _should_skip_inherited_auth(
        basic,
        access=access,
    ):
        locations.append(
            AuthRequiringLocation(
                path=path,
                auth_kind="basic",
                requires_tls=requires_tls,
                source=_source_location(basic.source),
            )
        )

    windows = sections.get(_WINDOWS_AUTH_SUFFIX)
    if _enabled_auth_section(windows) and not _should_skip_inherited_auth(
        windows,
        access=access,
    ):
        locations.append(
            AuthRequiringLocation(
                path=path,
                auth_kind="windows",
                requires_tls=requires_tls,
                source=_source_location(windows.source),
            )
        )

    authentication = sections.get(_AUTHENTICATION_SUFFIX)
    forms = sections.get(_FORMS_SUFFIX)
    if (
        _forms_auth_enabled(authentication, forms)
        and not _should_skip_inherited_auth(
            authentication,
            forms,
            access=access,
        )
    ):
        anchor = forms if forms is not None else authentication
        if anchor is not None:
            locations.append(
                AuthRequiringLocation(
                    path=path,
                    auth_kind="forms",
                    requires_tls=requires_tls,
                    source=_source_location(anchor.source),
                )
            )

    authorization = sections.get(_AUTHORIZATION_SUFFIX)
    implicit_auth_source = _implicit_auth_source(authorization)
    if implicit_auth_source is not None and not _should_skip_inherited_auth(
        authorization,
        access=access,
    ):
        locations.append(
            AuthRequiringLocation(
                path=path,
                auth_kind="implicit",
                requires_tls=requires_tls,
                source=_source_location(implicit_auth_source),
            )
        )

    return locations


def _enabled_auth_section(section: IISEffectiveSection | None) -> bool:
    if section is None:
        return False
    return section.attributes.get("enabled", "").strip().lower() == "true"


def _forms_auth_enabled(
    authentication: IISEffectiveSection | None,
    forms: IISEffectiveSection | None,
) -> bool:
    if authentication is None:
        return False
    return authentication.attributes.get("mode", "").strip().lower() == "forms"


def _implicit_auth_source(
    authorization: IISEffectiveSection | None,
) -> IISSourceRef | None:
    if authorization is None:
        return None
    for child in authorization.children:
        if child.tag.lower() != "deny":
            continue
        if not _contains_user_token(child.attributes.get("users"), "?"):
            continue
        return child.source
    return None


def _contains_user_token(value: str | None, token: str) -> bool:
    if not value:
        return False
    return token in {
        candidate.strip()
        for candidate in value.split(",")
        if candidate.strip()
    }


def _scope_requires_tls(
    listen_points: list[NormalizedListenPoint],
    access: IISEffectiveSection | None,
) -> bool:
    requires_ssl = _access_requires_ssl(access)
    if not listen_points:
        return requires_ssl

    has_http = any(not listen_point.tls for listen_point in listen_points)
    if has_http:
        return requires_ssl

    return any(listen_point.tls for listen_point in listen_points)


def _access_requires_ssl(access: IISEffectiveSection | None) -> bool:
    if access is None:
        return False
    ssl_flags = access.attributes.get("sslFlags", "")
    return "ssl" in {
        token.strip().lower()
        for token in ssl_flags.replace(";", ",").split(",")
        if token.strip()
    }


def _should_skip_inherited_auth(
    *sections: IISEffectiveSection | None,
    access: IISEffectiveSection | None,
) -> bool:
    relevant_sections = [section for section in sections if section is not None]
    if not relevant_sections:
        return True
    if any(section.location_path is None for section in relevant_sections):
        return False
    if any(not _is_pure_inherited_section(section) for section in relevant_sections):
        return False
    return access is None or _is_pure_inherited_section(access)


def _is_pure_inherited_section(section: IISEffectiveSection) -> bool:
    if section.location_path is None:
        return False
    return not any(
        origin.xml_path and "location[@path=" in origin.xml_path.lower()
        for origin in section.origin_chain
    )


def _location_path(location_path: str | None) -> str:
    if location_path is None:
        return "/"
    normalized = location_path.replace("\\", "/").strip("/")
    return f"/{normalized}" if normalized else "/"


def _source_location(source: IISSourceRef) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="xml",
        file_path=source.file_path or "",
        line=source.line,
        xml_path=source.xml_path,
    )


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
