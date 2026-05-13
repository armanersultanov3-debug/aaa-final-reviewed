"""Normalized security-relevant entities extracted from server-specific ASTs.

This module defines a thin, server-agnostic data model used by universal rules.
Each server has its own normalizer that maps native AST/effective-config data
into these structures on a best-effort basis.  Fields that a server cannot
populate are left as ``None``; universal rules skip silently in that case.

Every normalized entity carries a :class:`SourceRef` that points back to the
original AST node so findings remain traceable.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Literal, cast

from webconf_audit.models import SourceLocation

ListenAddressKind = Literal[
    "wildcard_ipv4",
    "wildcard_ipv6",
    "loopback",
    "specific",
    "unix",
]


@dataclass(frozen=True)
class SourceRef:
    """Back-reference to the original AST node that produced this entity."""

    server_type: str  # "nginx" | "apache" | "lighttpd" | "iis"
    file_path: str
    line: int | None = None
    xml_path: str | None = None  # IIS only
    details: str | None = None


# ---------------------------------------------------------------------------
# Listen points
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedListenPoint:
    """A single listener endpoint the server is configured to expose.

    ``port`` is ``0`` for non-TCP listeners such as unix sockets.
    """

    port: int
    protocol: str  # "http" | "https"
    tls: bool
    source: SourceRef
    address: str | None = None  # "0.0.0.0", "127.0.0.1", "*", etc.
    address_kind: ListenAddressKind = cast(ListenAddressKind, None)

    def __post_init__(self) -> None:
        if self.address_kind is None:
            object.__setattr__(
                self,
                "address_kind",
                _classify_listen_address(self.address),
            )


# ---------------------------------------------------------------------------
# TLS configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedTLS:
    """TLS-related configuration for a scope.

    *protocols* and *ciphers* are ``None`` when the server does not expose
    the information (e.g. IIS stores TLS protocol config in the registry,
    not in web.config).  Universal rules treat ``None`` as "unknown — skip".
    """

    source: SourceRef
    protocols: list[str] | None = None  # ["TLSv1", "TLSv1.2", …] or None
    ciphers: str | None = None  # raw cipher string or None
    certificate: str | None = None
    certificate_key: str | None = None
    require_ssl: bool | None = None  # IIS sslFlags concept; None = unknown


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedSecurityHeader:
    """A single security-relevant response header."""

    name: str  # lowercase: "strict-transport-security", "x-frame-options", …
    value: str | None  # raw value if present
    source: SourceRef


# ---------------------------------------------------------------------------
# Access / disclosure policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedAccessPolicy:
    """Coarse access-control and information-disclosure flags for a scope.

    *server_identification_disclosed* covers a heterogeneous set of settings:
    Nginx ``server_tokens``, Apache ``ServerTokens``/``ServerSignature``,
    Lighttpd ``server.tag``, IIS ``enableVersionHeader``.  The common
    denominator is "server name and/or version information is sent to
    clients".
    """

    source: SourceRef
    directory_listing: bool | None = None
    server_identification_disclosed: bool | None = None
    debug_mode: bool | None = None


# ---------------------------------------------------------------------------
# Authentication-requiring routes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthRequiringLocation:
    path: str
    auth_kind: str
    requires_tls: bool
    source: SourceLocation


# ---------------------------------------------------------------------------
# Scope & top-level container
# ---------------------------------------------------------------------------


@dataclass
class NormalizedScope:
    """One logical configuration scope.

    Maps to a Nginx ``server`` block, Apache ``<VirtualHost>``, Lighttpd
    global/conditional scope, or IIS location path.
    """

    scope_name: str | None = None
    listen_points: list[NormalizedListenPoint] = field(default_factory=list)
    tls: NormalizedTLS | None = None
    security_headers: list[NormalizedSecurityHeader] = field(default_factory=list)
    access_policy: NormalizedAccessPolicy | None = None


@dataclass
class NormalizedConfig:
    """Server-agnostic normalized configuration for universal rules."""

    server_type: str  # "nginx" | "apache" | "lighttpd" | "iis"
    scopes: list[NormalizedScope] = field(default_factory=list)
    auth_requiring_locations: tuple[AuthRequiringLocation, ...] = field(default_factory=tuple)


__all__ = [
    "NormalizedAccessPolicy",
    "AuthRequiringLocation",
    "ListenAddressKind",
    "NormalizedConfig",
    "NormalizedListenPoint",
    "NormalizedScope",
    "NormalizedSecurityHeader",
    "NormalizedTLS",
    "SourceRef",
]


def _classify_listen_address(address: str | None) -> ListenAddressKind:
    if address is None or address == "" or address == "*" or address == "0.0.0.0":
        return "wildcard_ipv4"

    normalized = address.strip().lower()
    if normalized.startswith("unix:"):
        return "unix"

    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]

    if normalized == "::":
        return "wildcard_ipv6"

    try:
        parsed = ipaddress.ip_address(normalized)
    except ValueError:
        return "specific"

    if parsed.is_loopback:
        return "loopback"
    if parsed.version == 4 and parsed == ipaddress.IPv4Address("0.0.0.0"):
        return "wildcard_ipv4"
    if parsed.version == 6 and parsed == ipaddress.IPv6Address("::"):
        return "wildcard_ipv6"
    return "specific"
