"""Reviewed exact-build defaults for IIS SChannel evidence resolution."""

from __future__ import annotations

from webconf_audit.local.iis.schannel_models import (
    EffectiveState,
    SchannelDefaultCatalogEntry,
    SchannelOSIdentity,
)

_WINDOWS_SERVER_2022_DEFAULT_ORDER = (
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
)

_CATALOG = (
    SchannelDefaultCatalogEntry(
        catalog_id="windows-server-2022-build-20348",
        product_match="Windows Server 2022",
        build_min=20348,
        build_max=20348,
        source_url="https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-",
        reviewed_on="2026-06-15",
        protocol_defaults={
            "SSLv2": "disabled",
            "SSLv3": "disabled",
            "TLSv1.0": "enabled",
            "TLSv1.1": "enabled",
            "TLSv1.2": "enabled",
            "TLSv1.3": "enabled",
        },
        cipher_defaults={
            "AES 128/128": "enabled",
            "AES 256/256": "enabled",
        },
        cipher_suite_order=_WINDOWS_SERVER_2022_DEFAULT_ORDER,
    ),
)

_CIPHER_SUITE_ORDER_SOURCE_URL = (
    "https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022"
)


def resolve_default_catalog_entry(
    os_identity: SchannelOSIdentity,
) -> SchannelDefaultCatalogEntry | None:
    """Resolve a reviewed exact-build default catalog entry for ``os_identity``."""
    product_name = (os_identity.product_name or "").strip()
    build = os_identity.build
    if not product_name or build is None:
        return None

    for entry in _CATALOG:
        if entry.product_match in product_name and entry.build_min <= build <= entry.build_max:
            return entry
    return None


def protocol_default_state(
    os_identity: SchannelOSIdentity,
    protocol_name: str,
) -> tuple[EffectiveState, str | None, str | None]:
    """Resolve a reviewed effective default protocol state, if available."""
    entry = resolve_default_catalog_entry(os_identity)
    if entry is None:
        return "unknown", None, None
    return (
        entry.protocol_defaults.get(protocol_name, "unknown"),
        entry.source_url,
        entry.catalog_id,
    )


def cipher_default_state(
    os_identity: SchannelOSIdentity,
    cipher_name: str,
) -> tuple[EffectiveState, str | None, str | None]:
    """Resolve a reviewed effective default cipher state, if available."""
    entry = resolve_default_catalog_entry(os_identity)
    if entry is None:
        return "unknown", None, None
    return (
        entry.cipher_defaults.get(cipher_name, "unknown"),
        entry.source_url,
        entry.catalog_id,
    )


def cipher_suite_order_default(
    os_identity: SchannelOSIdentity,
) -> tuple[tuple[str, ...], str | None, str | None]:
    """Resolve a reviewed default cipher-suite order, if available."""
    entry = resolve_default_catalog_entry(os_identity)
    if entry is None or not entry.cipher_suite_order:
        return (), None, None
    return entry.cipher_suite_order, _CIPHER_SUITE_ORDER_SOURCE_URL, entry.catalog_id


__all__ = [
    "cipher_default_state",
    "cipher_suite_order_default",
    "protocol_default_state",
    "resolve_default_catalog_entry",
]
