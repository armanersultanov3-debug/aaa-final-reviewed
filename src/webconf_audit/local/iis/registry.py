"""IIS TLS data sourced from the Windows SChannel registry.

IIS XML configuration covers ``sslFlags`` and HTTPS bindings, while the
effective TLS protocol and cipher policy usually lives under
``HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL``.
This module reads that data either from the live Windows registry or from a
JSON export so the IIS normalizer can feed universal TLS rules.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from webconf_audit.local.normalized import SourceRef
from webconf_audit.models import AnalysisIssue, SourceLocation

_LIVE_SOURCE_LABEL = "live SChannel registry"

_SCHANNEL_BASE = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
_SCHANNEL_SOURCE_PATH = "HKLM/SYSTEM/CurrentControlSet/Control/SecurityProviders/SCHANNEL"
_CIPHER_SUITE_ORDER_PATH = (
    r"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
)

# SChannel registry protocol names -> universal-rule protocol identifiers.
_PROTOCOL_NAMES: dict[str, str] = {
    "SSL 2.0": "SSLv2",
    "SSL 3.0": "SSLv3",
    "TLS 1.0": "TLSv1.0",
    "TLS 1.1": "TLSv1.1",
    "TLS 1.2": "TLSv1.2",
    "TLS 1.3": "TLSv1.3",
}


@dataclass(frozen=True, slots=True)
class IISRegistryTLS:
    """SChannel-derived TLS policy snapshot.

    ``None`` means the registry/export did not include that class of data.
    An empty list means the source was present and no enabled entries were
    found.
    """

    protocols_enabled: list[str] | None = None
    ciphers_enabled: list[str] | None = None
    cipher_suite_order: list[str] | None = None
    source_kind: Literal["live", "export"] = "live"
    source_label: str = _LIVE_SOURCE_LABEL
    host: str | None = None

    @property
    def has_data(self) -> bool:
        return (
            self.protocols_enabled is not None
            or self.ciphers_enabled is not None
            or self.cipher_suite_order is not None
        )

    @property
    def source_file_path(self) -> str:
        if self.source_kind == "live":
            host = self.host or "localhost"
            return f"registry://{host}/{_SCHANNEL_SOURCE_PATH}"
        return self.source_label

    @property
    def source_details(self) -> str:
        if self.source_kind == "live":
            host = self.host or "localhost"
            return f"IIS TLS data sourced from local SChannel registry on host {host}"
        return f"IIS TLS data sourced from SChannel registry export: {self.source_label}"

    def source_ref(self) -> SourceRef:
        return SourceRef(
            server_type="iis",
            file_path=self.source_file_path,
            details=self.source_details,
        )

    def source_issue(self) -> AnalysisIssue:
        return AnalysisIssue(
            code="iis_tls_registry_source",
            level="info",
            message=self.source_details,
            location=SourceLocation(
                mode="local",
                kind="tls",
                file_path=self.source_file_path,
                details=self.source_details,
            ),
            metadata={
                "source_kind": self.source_kind,
                "host": self.host,
                "protocols_known": self.protocols_enabled is not None,
                "ciphers_known": self.ciphers_enabled is not None,
                "cipher_suite_order_known": self.cipher_suite_order is not None,
            },
        )


def load_registry_export(
    export_path: str | os.PathLike[str],
) -> tuple[IISRegistryTLS | None, list[AnalysisIssue]]:
    """Load a JSON-formatted SChannel registry export.

    Expected shape::

        {
          "schannel": {
            "protocols": {
              "TLS 1.0": {"server_enabled": 1, "server_disabled_by_default": 0}
            },
            "ciphers": {
              "RC4 40/128": {"enabled": 4294967295}
            },
            "cipher_suite_order": [
              "TLS_AES_256_GCM_SHA384",
              "TLS_AES_128_GCM_SHA256"
            ]
          }
        }
    """
    export_path_str = os.fspath(export_path)
    path = Path(export_path_str)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [
            _export_issue(export_path_str, f"Cannot read TLS registry export: {exc}")
        ]

    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, [
            _export_issue(export_path_str, f"Invalid JSON in TLS registry export: {exc}")
        ]

    if not isinstance(raw, dict):
        return None, [
            _export_issue(export_path_str, "TLS registry export must be a JSON object.")
        ]

    schannel = raw.get("schannel")
    if not isinstance(schannel, dict):
        return None, [
            _export_issue(
                export_path_str,
                "TLS registry export is missing the 'schannel' object.",
            )
        ]

    snapshot = IISRegistryTLS(
        protocols_enabled=_parse_export_protocols(schannel.get("protocols")),
        ciphers_enabled=_parse_export_ciphers(schannel.get("ciphers")),
        cipher_suite_order=_parse_export_cipher_suite_order(schannel),
        source_kind="export",
        source_label=str(path),
    )
    if not snapshot.has_data:
        return None, [
            _export_issue(
                export_path_str,
                "TLS registry export does not contain protocol or cipher data.",
            )
        ]
    return snapshot, []


def resolve_registry_tls(
    registry_source: str | os.PathLike[str] | None = None,
    *,
    use_live_registry: bool = True,
) -> tuple[IISRegistryTLS | None, list[AnalysisIssue]]:
    """Resolve IIS TLS registry data from an export or the live host.

    Explicit JSON exports take precedence over live registry discovery. The
    live path is a no-op on non-Windows hosts.
    """
    if registry_source is not None:
        return load_registry_export(registry_source)
    if not use_live_registry:
        return None, []
    return read_live_registry()


def _parse_export_protocols(value: object) -> list[str] | None:
    if not isinstance(value, dict):
        return None

    enabled: list[str] = []
    for raw_name, entry in value.items():
        normalized = _PROTOCOL_NAMES.get(str(raw_name).strip())
        if normalized is None or not isinstance(entry, dict):
            continue
        if _protocol_effectively_enabled(
            entry.get("server_enabled"),
            entry.get("server_disabled_by_default"),
        ):
            enabled.append(normalized)
    return enabled


def _parse_export_ciphers(value: object) -> list[str] | None:
    if not isinstance(value, dict):
        return None

    enabled: list[str] = []
    for name, entry in value.items():
        if not isinstance(entry, dict):
            continue
        if _is_truthy_dword(entry.get("enabled")):
            enabled.append(str(name))
    return enabled


def _parse_export_cipher_suite_order(schannel: dict[str, object]) -> list[str] | None:
    value = schannel.get("cipher_suite_order")
    if value is None:
        value = schannel.get("cipher_suites")
    return _parse_cipher_suite_order_value(value)


class _RegistryReader(Protocol):
    """Minimal registry reader interface used by :func:`read_live_registry`."""

    def open_subkeys(self, parent: str) -> list[str] | None:
        ...

    def query_dword(self, parent: str, value_name: str) -> int | None:
        ...

    def query_value(self, parent: str, value_name: str) -> object | None:
        ...


def read_live_registry(
    reader: _RegistryReader | None = None,
) -> tuple[IISRegistryTLS | None, list[AnalysisIssue]]:
    """Read SChannel keys from the live Windows registry.

    Returns ``(None, [])`` on non-Windows hosts. ``reader`` is injectable so
    tests can exercise the live path without touching ``winreg``.
    """
    if reader is None:
        if sys.platform != "win32":
            return None, []
        reader = _WinregReader()

    protocols: list[str] = []
    protocols_known = False
    for raw_name, normalized in _PROTOCOL_NAMES.items():
        server_path = f"{_SCHANNEL_BASE}\\Protocols\\{raw_name}\\Server"
        server_enabled = reader.query_dword(server_path, "Enabled")
        server_disabled_by_default = reader.query_dword(
            server_path,
            "DisabledByDefault",
        )
        if server_enabled is not None or server_disabled_by_default is not None:
            protocols_known = True
        if _protocol_effectively_enabled(server_enabled, server_disabled_by_default):
            protocols.append(normalized)

    cipher_subkeys = reader.open_subkeys(f"{_SCHANNEL_BASE}\\Ciphers")
    ciphers: list[str] | None = None
    if cipher_subkeys is not None:
        ciphers = []
        for cipher_name in cipher_subkeys:
            cipher_path = f"{_SCHANNEL_BASE}\\Ciphers\\{cipher_name}"
            if _is_truthy_dword(reader.query_dword(cipher_path, "Enabled")):
                ciphers.append(cipher_name)

    cipher_suite_order = _parse_cipher_suite_order_value(
        reader.query_value(_CIPHER_SUITE_ORDER_PATH, "Functions"),
    )

    snapshot = IISRegistryTLS(
        protocols_enabled=protocols if protocols_known else None,
        ciphers_enabled=ciphers,
        cipher_suite_order=cipher_suite_order,
        source_kind="live",
        source_label=_LIVE_SOURCE_LABEL,
        host=socket.gethostname() or None,
    )
    if not snapshot.has_data:
        return None, []
    return snapshot, []


class _WinregReader:
    """Concrete ``winreg``-backed reader, imported lazily for portability."""

    def __init__(self) -> None:
        import winreg  # noqa: PLC0415 - Windows-only stdlib import.

        self._winreg = winreg
        self._root = winreg.HKEY_LOCAL_MACHINE

    def open_subkeys(self, parent: str) -> list[str] | None:
        names: list[str] = []
        try:
            handle = self._winreg.OpenKey(self._root, parent)
        except OSError:
            return None
        try:
            index = 0
            while True:
                try:
                    names.append(self._winreg.EnumKey(handle, index))
                except OSError:
                    break
                index += 1
        finally:
            handle.Close()
        return names

    def query_dword(self, parent: str, value_name: str) -> int | None:
        value = self.query_value(parent, value_name)
        if isinstance(value, int):
            return value
        return None

    def query_value(self, parent: str, value_name: str) -> object | None:
        try:
            handle = self._winreg.OpenKey(self._root, parent)
        except OSError:
            return None
        try:
            try:
                value, _kind = self._winreg.QueryValueEx(handle, value_name)
            except OSError:
                return None
        finally:
            handle.Close()
        return value


def _protocol_effectively_enabled(
    server_enabled: object,
    server_disabled_by_default: object,
) -> bool:
    # Microsoft documents a protocol as effectively enabled iff
    # Enabled != 0 and DisabledByDefault == 0. Missing values mean OS default,
    # which depends on the Windows version, so absence remains unknown.
    if not isinstance(server_enabled, int) or not isinstance(server_disabled_by_default, int):
        return False
    return server_enabled != 0 and server_disabled_by_default == 0


def _is_truthy_dword(value: object) -> bool:
    return isinstance(value, int) and value != 0


def _parse_cipher_suite_order_value(value: object) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("Functions") or value.get("functions")
    if isinstance(value, str):
        return _split_cipher_suite_order(value)
    if isinstance(value, list | tuple):
        suites: list[str] = []
        for item in value:
            if isinstance(item, str):
                suites.extend(_split_cipher_suite_order(item))
        return suites
    return None


def _split_cipher_suite_order(value: str) -> list[str]:
    return [
        item.strip()
        for item in value.replace("\r", "\n").replace("\n", ",").split(",")
        if item.strip()
    ]


def _export_issue(export_path: str, message: str) -> AnalysisIssue:
    return AnalysisIssue(
        code="iis_tls_registry_export_error",
        level="warning",
        message=message,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=export_path,
        ),
    )


__all__ = [
    "IISRegistryTLS",
    "load_registry_export",
    "read_live_registry",
    "resolve_registry_tls",
]
