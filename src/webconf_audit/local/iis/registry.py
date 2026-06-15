"""IIS TLS data sourced from the Windows SChannel registry."""

from __future__ import annotations

import json
import os
import platform
import socket
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from webconf_audit.local.iis.schannel_defaults import (
    cipher_default_state,
    cipher_suite_order_default,
    protocol_default_state,
)
from webconf_audit.local.iis.schannel_models import (
    CompletenessState,
    EffectiveState,
    IISSchannelEvidence,
    SchannelCipherEvidence,
    SchannelCipherSuiteOrderEvidence,
    SchannelCollectionIssue,
    SchannelCompleteness,
    SchannelEvidenceData,
    SchannelOSIdentity,
    SchannelProtocolEvidence,
    SchannelProtocolRegistryEvidence,
    SchannelReadStatus,
    SchannelRegistryStringList,
    SchannelRegistryValue,
    SchannelState,
)
from webconf_audit.local.normalized import SourceRef
from webconf_audit.models import AnalysisIssue, SourceLocation

_LIVE_SOURCE_LABEL = "live SChannel registry"

_SCHANNEL_BASE = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
_SCHANNEL_SOURCE_PATH = "HKLM/SYSTEM/CurrentControlSet/Control/SecurityProviders/SCHANNEL"
_CIPHER_SUITE_ORDER_PATH = (
    r"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
)
_WINDOWS_VERSION_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

# SChannel registry protocol names -> universal-rule protocol identifiers.
_PROTOCOL_NAMES: dict[str, str] = {
    "SSL 2.0": "SSLv2",
    "SSL 3.0": "SSLv3",
    "TLS 1.0": "TLSv1.0",
    "TLS 1.1": "TLSv1.1",
    "TLS 1.2": "TLSv1.2",
    "TLS 1.3": "TLSv1.3",
}

_SYNTHETIC_CIPHERS = ("AES 128/128", "AES 256/256")
_KNOWN_PROTOCOLS = tuple(_PROTOCOL_NAMES.values())


class SchannelEvidenceLoadError(ValueError):
    """Raised when an explicit SChannel export cannot be loaded safely."""

    def __init__(self, code: str, message: str, *, path: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.path = path


@dataclass(frozen=True, slots=True)
class IISRegistryTLS:
    """Deprecated v1-compatible wrapper around canonical SChannel evidence."""

    protocols_enabled: list[str] | None = None
    ciphers_enabled: list[str] | None = None
    cipher_suite_order: list[str] | None = None
    source_kind: str = "live"
    source_label: str = _LIVE_SOURCE_LABEL
    host: str | None = None
    evidence: IISSchannelEvidence | None = None

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
        if self.evidence is not None:
            return self.evidence.source_ref()
        return SourceRef(
            server_type="iis",
            file_path=self.source_file_path,
            details=self.source_details,
        )

    def source_issue(self) -> AnalysisIssue:
        if self.evidence is not None:
            return self.evidence.source_issue()
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

    def to_evidence(self) -> IISSchannelEvidence:
        if self.evidence is not None:
            return self.evidence
        return _legacy_wrapper_to_evidence(self)

    @classmethod
    def from_evidence(cls, evidence: IISSchannelEvidence) -> "IISRegistryTLS":
        return cls(
            protocols_enabled=evidence.enabled_protocols()
            if evidence.completeness.protocols != "unknown"
            else None,
            ciphers_enabled=evidence.enabled_ciphers()
            if evidence.completeness.ciphers != "unknown"
            else None,
            cipher_suite_order=evidence.effective_cipher_suite_order(),
            source_kind=evidence.source_kind,
            source_label=evidence.source_label,
            host=evidence.host,
            evidence=evidence,
        )


@dataclass(frozen=True, slots=True)
class _ReadResult:
    status: SchannelReadStatus
    value: object | None = None
    error: str | None = None


class _RegistryReader(Protocol):
    """Structured registry reader interface used by ``read_live_schannel``."""

    def open_subkeys(self, parent: str) -> object:
        ...

    def query_value(self, parent: str, value_name: str) -> object:
        ...


def load_schannel_export(path: str | os.PathLike[str]) -> IISSchannelEvidence:
    """Load a versioned SChannel export and normalize it to canonical v2 evidence."""
    export_path = Path(path)
    try:
        text = export_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"Cannot read TLS registry export: {exc}",
            path=str(export_path),
        ) from exc

    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"Invalid JSON in TLS registry export: {exc}",
            path=str(export_path),
        ) from exc

    if not isinstance(raw, dict):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export must be a JSON object.",
            path=str(export_path),
        )

    schema_version = raw.get("schema_version")
    if schema_version is not None and schema_version != 2:
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"Unsupported TLS registry export schema_version: {schema_version!r}.",
            path=str(export_path),
        )
    if schema_version == 2:
        return _load_v2_export(raw, str(export_path))
    if isinstance(raw.get("schannel"), dict):
        return _adapt_v1_export(raw, str(export_path))
    raise SchannelEvidenceLoadError(
        "iis_tls_registry_export_error",
        "TLS registry export must declare schema_version 2 or a legacy top-level 'schannel' object.",
        path=str(export_path),
    )


def read_live_schannel(
    reader: _RegistryReader | None = None,
) -> tuple[IISSchannelEvidence | None, list[AnalysisIssue]]:
    """Read canonical SChannel evidence from the live Windows registry."""
    if reader is None:
        if sys.platform != "win32":
            return None, []
        reader = _WinregReader()

    host = socket.gethostname() or None
    captured_at = datetime.now(UTC)
    collection_issues: list[SchannelCollectionIssue] = []

    os_identity, os_completeness = _read_live_os_identity(reader, collection_issues)
    protocols, protocols_completeness = _read_live_protocols(reader, os_identity, collection_issues)
    ciphers, ciphers_completeness = _read_live_ciphers(reader, os_identity, collection_issues)
    cipher_suite_order, order_completeness = _read_live_cipher_suite_order(
        reader,
        os_identity,
        collection_issues,
    )

    evidence = IISSchannelEvidence(
        host=host,
        captured_at=captured_at,
        os=os_identity,
        completeness=SchannelCompleteness(
            os_build=os_completeness,
            protocols=protocols_completeness,
            ciphers=ciphers_completeness,
            cipher_suite_order=order_completeness,
        ),
        schannel=SchannelEvidenceData(
            protocols=tuple(protocols),
            ciphers=tuple(ciphers),
            cipher_suite_order=cipher_suite_order,
        ),
        collection_issues=tuple(collection_issues),
        source_kind="live",
        source_label=_LIVE_SOURCE_LABEL,
        input_schema_version=2,
        adapted_to_v2=False,
    )
    if not evidence.has_data and not collection_issues:
        return None, []
    return evidence, evidence.issue_records()


def resolve_schannel_state(
    *,
    enabled: SchannelRegistryValue,
    disabled_by_default: SchannelRegistryValue | None = None,
    completeness: CompletenessState,
    default_effective_state: EffectiveState = "unknown",
) -> tuple[SchannelState, EffectiveState, str]:
    """Resolve canonical SChannel state semantics for protocols or ciphers."""
    if disabled_by_default is None:
        return _resolve_cipher_state(
            enabled=enabled,
            completeness=completeness,
            default_effective_state=default_effective_state,
        )
    return _resolve_protocol_state(
        enabled=enabled,
        disabled_by_default=disabled_by_default,
        completeness=completeness,
        default_effective_state=default_effective_state,
    )


def resolve_schannel_evidence(
    registry_source: str | os.PathLike[str] | None = None,
    *,
    use_live_registry: bool = True,
) -> tuple[IISSchannelEvidence | None, list[AnalysisIssue]]:
    """Resolve canonical IIS SChannel evidence from an export or the live host."""
    if registry_source is not None:
        try:
            evidence = load_schannel_export(registry_source)
        except SchannelEvidenceLoadError as exc:
            return None, [_export_issue(exc)]
        return evidence, evidence.issue_records()
    if not use_live_registry:
        return None, []
    return read_live_schannel()


def load_registry_export(
    export_path: str | os.PathLike[str],
) -> tuple[IISRegistryTLS | None, list[AnalysisIssue]]:
    """Deprecated compatibility wrapper for legacy callers."""
    evidence, issues = resolve_schannel_evidence(export_path, use_live_registry=False)
    return (IISRegistryTLS.from_evidence(evidence) if evidence is not None else None), issues


def read_live_registry(
    reader: _RegistryReader | None = None,
) -> tuple[IISRegistryTLS | None, list[AnalysisIssue]]:
    """Deprecated compatibility wrapper for legacy callers."""
    evidence, issues = read_live_schannel(reader)
    return (IISRegistryTLS.from_evidence(evidence) if evidence is not None else None), issues


def resolve_registry_tls(
    registry_source: str | os.PathLike[str] | None = None,
    *,
    use_live_registry: bool = True,
) -> tuple[IISRegistryTLS | None, list[AnalysisIssue]]:
    """Deprecated compatibility wrapper preserving the historical entry point."""
    evidence, issues = resolve_schannel_evidence(
        registry_source,
        use_live_registry=use_live_registry,
    )
    return (IISRegistryTLS.from_evidence(evidence) if evidence is not None else None), issues


def coerce_schannel_evidence(
    value: IISSchannelEvidence | IISRegistryTLS | None,
) -> IISSchannelEvidence | None:
    """Coerce legacy IIS registry wrappers to canonical evidence."""
    if value is None:
        return None
    if isinstance(value, IISRegistryTLS):
        return value.to_evidence()
    return value


def _load_v2_export(raw: dict[str, object], export_path: str) -> IISSchannelEvidence:
    if raw.get("kind") != "iis-schannel-evidence":
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export kind must be 'iis-schannel-evidence'.",
            path=export_path,
        )

    captured_at = _parse_captured_at(raw.get("captured_at"), export_path)
    os_identity = _parse_os_identity(raw.get("os"), export_path)
    completeness = _parse_completeness(raw.get("completeness"), export_path)
    explicit_issues = _parse_collection_issues(raw.get("collection_issues"), export_path)
    schannel = raw.get("schannel")
    if not isinstance(schannel, dict):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export is missing the 'schannel' object.",
            path=export_path,
        )

    protocols = _parse_v2_protocols(
        schannel.get("protocols"),
        completeness.protocols,
        os_identity,
        export_path,
    )
    ciphers = _parse_v2_ciphers(
        schannel.get("ciphers"),
        completeness.ciphers,
        os_identity,
        export_path,
    )
    cipher_suite_order = _parse_v2_cipher_suite_order(
        schannel.get("cipher_suite_order"),
        completeness.cipher_suite_order,
        os_identity,
        export_path,
    )
    _validate_collection_issue_completeness(explicit_issues, completeness, export_path)

    evidence = IISSchannelEvidence(
        host=_optional_string(raw.get("host")),
        captured_at=captured_at,
        os=os_identity,
        completeness=completeness,
        schannel=SchannelEvidenceData(
            protocols=tuple(protocols),
            ciphers=tuple(ciphers),
            cipher_suite_order=cipher_suite_order,
        ),
        collection_issues=tuple(explicit_issues),
        source_kind="export",
        source_label=export_path,
        input_schema_version=2,
        adapted_to_v2=False,
    )
    if not evidence.has_data:
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export does not contain protocol, cipher, or cipher-suite data.",
            path=export_path,
        )
    return evidence


def _adapt_v1_export(raw: dict[str, object], export_path: str) -> IISSchannelEvidence:
    schannel = raw.get("schannel")
    if not isinstance(schannel, dict):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export is missing the 'schannel' object.",
            path=export_path,
        )

    explicit_protocols = _parse_v1_protocols(schannel.get("protocols"))
    explicit_ciphers = _parse_v1_ciphers(schannel.get("ciphers"))
    explicit_order = _parse_v1_cipher_suite_order(schannel)
    if not explicit_protocols and not explicit_ciphers and explicit_order is None:
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export does not contain protocol or cipher data.",
            path=export_path,
        )

    protocols: list[SchannelProtocolEvidence] = []
    for protocol_name in _KNOWN_PROTOCOLS:
        if protocol_name in explicit_protocols:
            protocols.append(
                SchannelProtocolEvidence(
                    name=protocol_name,
                    raw_name=protocol_name,
                    server=SchannelProtocolRegistryEvidence(
                        enabled=SchannelRegistryValue(present=True, value=1, status="present"),
                        disabled_by_default=SchannelRegistryValue(
                            present=True,
                            value=0,
                            status="present",
                        ),
                    ),
                    state="enabled",
                    effective_state="enabled",
                    state_reason="Legacy v1 export explicitly listed this protocol as enabled.",
                    source_path=f"{_SCHANNEL_SOURCE_PATH}/Protocols/{protocol_name}/Server",
                    completeness="partial",
                )
            )
        else:
            protocols.append(
                SchannelProtocolEvidence(
                    name=protocol_name,
                    raw_name=protocol_name,
                    server=SchannelProtocolRegistryEvidence(),
                    state="unknown",
                    effective_state="unknown",
                    state_reason=(
                        "Legacy v1 export omitted this protocol, so it cannot prove disabled "
                        "or default state."
                    ),
                    source_path=f"{_SCHANNEL_SOURCE_PATH}/Protocols/{protocol_name}/Server",
                    completeness="partial",
                )
            )

    cipher_names: list[str] = []
    seen_cipher_keys: set[str] = set()
    for raw_name in [*explicit_ciphers, *_SYNTHETIC_CIPHERS]:
        key = _normalize_cipher_key(raw_name)
        if key in seen_cipher_keys:
            continue
        seen_cipher_keys.add(key)
        cipher_names.append(raw_name)

    ciphers: list[SchannelCipherEvidence] = []
    for cipher_name in cipher_names:
        if cipher_name in explicit_ciphers:
            ciphers.append(
                SchannelCipherEvidence(
                    name=cipher_name,
                    raw_name=cipher_name,
                    enabled=SchannelRegistryValue(present=True, value=1, status="present"),
                    state="enabled",
                    effective_state="enabled",
                    state_reason="Legacy v1 export explicitly listed this cipher as enabled.",
                    source_path=f"{_SCHANNEL_SOURCE_PATH}/Ciphers/{cipher_name}",
                    completeness="partial",
                )
            )
        else:
            ciphers.append(
                SchannelCipherEvidence(
                    name=cipher_name,
                    raw_name=cipher_name,
                    enabled=SchannelRegistryValue(),
                    state="unknown",
                    effective_state="unknown",
                    state_reason=(
                        "Legacy v1 export omitted this cipher, so it cannot prove disabled "
                        "or default state."
                    ),
                    source_path=f"{_SCHANNEL_SOURCE_PATH}/Ciphers/{cipher_name}",
                    completeness="partial",
                )
            )

    if explicit_order is None:
        order_evidence = SchannelCipherSuiteOrderEvidence(
            raw_value=SchannelRegistryStringList(),
            order_source="unknown",
            effective_order=(),
            state_reason="Legacy v1 export did not include a cipher-suite order.",
            source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            completeness="unknown",
        )
    else:
        order_evidence = SchannelCipherSuiteOrderEvidence(
            raw_value=SchannelRegistryStringList(
                present=True,
                value=tuple(explicit_order),
                status="present",
            ),
            order_source="explicit",
            effective_order=tuple(explicit_order),
            state_reason="Legacy v1 export carried an explicit cipher-suite order.",
            source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            completeness="complete",
        )

    return IISSchannelEvidence(
        host=_optional_string(raw.get("host")),
        captured_at=datetime.now(UTC),
        os=SchannelOSIdentity(),
        completeness=SchannelCompleteness(
            os_build="unknown",
            protocols="partial",
            ciphers="partial",
            cipher_suite_order="complete" if explicit_order is not None else "unknown",
        ),
        schannel=SchannelEvidenceData(
            protocols=tuple(protocols),
            ciphers=tuple(ciphers),
            cipher_suite_order=order_evidence,
        ),
        collection_issues=(
            SchannelCollectionIssue(
                evidence_class="adapter",
                code="iis_tls_registry_v1_adapter_warning",
                message=(
                    "Legacy v1 TLS registry export was adapted to canonical v2 evidence; "
                    "omitted entries cannot prove disabled or default state."
                ),
            ),
        ),
        source_kind="export",
        source_label=export_path,
        input_schema_version=1,
        adapted_to_v2=True,
    )


def _parse_captured_at(value: object, export_path: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export requires a non-empty captured_at timestamp.",
            path=export_path,
        )
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"Invalid captured_at timestamp in TLS registry export: {value!r}.",
            path=export_path,
        ) from exc


def _parse_os_identity(value: object, export_path: str) -> SchannelOSIdentity:
    if value is None:
        return SchannelOSIdentity()
    if not isinstance(value, dict):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export os field must be an object.",
            path=export_path,
        )
    build = value.get("build")
    ubr = value.get("ubr")
    if build is not None and not isinstance(build, int):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export os.build must be an integer.",
            path=export_path,
        )
    if ubr is not None and not isinstance(ubr, int):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export os.ubr must be an integer when present.",
            path=export_path,
        )
    return SchannelOSIdentity(
        product_name=_optional_string(value.get("product_name")),
        version=_optional_string(value.get("version")),
        build=build,
        ubr=ubr,
        architecture=_optional_string(value.get("architecture")),
    )


def _parse_completeness(value: object, export_path: str) -> SchannelCompleteness:
    if not isinstance(value, dict):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export completeness field must be an object.",
            path=export_path,
        )
    parsed: dict[str, CompletenessState] = {}
    for field_name in ("os_build", "protocols", "ciphers", "cipher_suite_order"):
        raw_value = value.get(field_name)
        if raw_value not in {"complete", "partial", "unknown"}:
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                f"TLS registry export completeness.{field_name} must be complete, partial, or unknown.",
                path=export_path,
            )
        parsed[field_name] = raw_value
    return SchannelCompleteness(**parsed)


def _parse_collection_issues(value: object, export_path: str) -> list[SchannelCollectionIssue]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export collection_issues field must be an array.",
            path=export_path,
        )
    issues: list[SchannelCollectionIssue] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                "TLS registry export collection issues must be objects.",
                path=export_path,
            )
        evidence_class = entry.get("evidence_class")
        if evidence_class not in {
            "os_build",
            "protocols",
            "ciphers",
            "cipher_suite_order",
            "adapter",
        }:
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                "TLS registry export collection issue evidence_class is invalid.",
                path=export_path,
            )
        issues.append(
            SchannelCollectionIssue(
                evidence_class=evidence_class,
                code=_required_string(entry.get("code"), export_path, "collection issue code"),
                message=_required_string(
                    entry.get("message"),
                    export_path,
                    "collection issue message",
                ),
                path=_optional_string(entry.get("path")),
                severity="error" if entry.get("severity") == "error" else "warning",
            )
        )
    return issues


def _parse_v2_protocols(
    value: object,
    completeness: CompletenessState,
    os_identity: SchannelOSIdentity,
    export_path: str,
) -> list[SchannelProtocolEvidence]:
    if value is not None and not isinstance(value, dict):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export schannel.protocols must be an object when present.",
            path=export_path,
        )
    raw_protocols = value or {}
    seen: dict[str, str] = {}
    evidence_by_name: dict[str, SchannelProtocolEvidence] = {}
    for raw_name, entry in raw_protocols.items():
        if not isinstance(raw_name, str) or not isinstance(entry, dict):
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                "TLS registry export protocol entries must be object members.",
                path=export_path,
            )
        normalized = _normalize_protocol_name(raw_name)
        existing = seen.get(normalized)
        if existing is not None and existing != raw_name:
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                f"Duplicate normalized protocol names {existing!r} and {raw_name!r}.",
                path=export_path,
            )
        seen[normalized] = raw_name
        server = entry.get("server")
        if not isinstance(server, dict):
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                f"TLS registry export protocol {raw_name!r} requires a server object.",
                path=export_path,
            )
        enabled = _parse_v2_dword_value(
            server.get("enabled"),
            export_path,
            f"{raw_name} enabled",
        )
        disabled_by_default = _parse_v2_dword_value(
            server.get("disabled_by_default"),
            export_path,
            f"{raw_name} disabled_by_default",
        )
        evidence_by_name[normalized] = _build_protocol_evidence(
            name=normalized,
            raw_name=raw_name.strip(),
            enabled=enabled,
            disabled_by_default=disabled_by_default,
            completeness=completeness,
            os_identity=os_identity,
        )
    for protocol_name in _KNOWN_PROTOCOLS:
        evidence_by_name.setdefault(
            protocol_name,
            _build_protocol_evidence(
                name=protocol_name,
                raw_name=protocol_name,
                enabled=SchannelRegistryValue(),
                disabled_by_default=SchannelRegistryValue(),
                completeness=completeness,
                os_identity=os_identity,
            ),
        )
    return sorted(evidence_by_name.values(), key=lambda entry: entry.name)


def _parse_v2_ciphers(
    value: object,
    completeness: CompletenessState,
    os_identity: SchannelOSIdentity,
    export_path: str,
) -> list[SchannelCipherEvidence]:
    if value is not None and not isinstance(value, dict):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            "TLS registry export schannel.ciphers must be an object when present.",
            path=export_path,
        )
    raw_ciphers = value or {}
    seen: dict[str, str] = {}
    evidence_by_name: dict[str, SchannelCipherEvidence] = {}
    for raw_name, entry in raw_ciphers.items():
        if not isinstance(raw_name, str) or not isinstance(entry, dict):
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                "TLS registry export cipher entries must be object members.",
                path=export_path,
            )
        normalized_key = _normalize_cipher_key(raw_name)
        existing = seen.get(normalized_key)
        if existing is not None and existing != raw_name:
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                f"Duplicate normalized cipher names {existing!r} and {raw_name!r}.",
                path=export_path,
            )
        seen[normalized_key] = raw_name
        evidence_by_name[normalized_key] = _build_cipher_evidence(
            name=raw_name.strip(),
            raw_name=raw_name.strip(),
            enabled=_parse_v2_dword_value(
                entry.get("enabled"),
                export_path,
                f"{raw_name} enabled",
            ),
            completeness=completeness,
            os_identity=os_identity,
        )
    for cipher_name in _SYNTHETIC_CIPHERS:
        evidence_by_name.setdefault(
            _normalize_cipher_key(cipher_name),
            _build_cipher_evidence(
                name=cipher_name,
                raw_name=cipher_name,
                enabled=SchannelRegistryValue(),
                completeness=completeness,
                os_identity=os_identity,
            ),
        )
    return sorted(evidence_by_name.values(), key=lambda entry: entry.name.lower())


def _parse_v2_cipher_suite_order(
    value: object,
    completeness: CompletenessState,
    os_identity: SchannelOSIdentity,
    export_path: str,
) -> SchannelCipherSuiteOrderEvidence:
    raw_value = _parse_v2_string_list_value(
        value,
        export_path,
        "cipher_suite_order",
    )
    effective_order, default_source, default_catalog_ref = cipher_suite_order_default(os_identity)
    if raw_value.present and raw_value.status == "present":
        return SchannelCipherSuiteOrderEvidence(
            raw_value=raw_value,
            order_source="explicit",
            effective_order=raw_value.value,
            state_reason="Cipher-suite order was explicitly configured in the evidence source.",
            source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            completeness=completeness,
        )
    if raw_value.status in {"access-denied", "malformed", "error"}:
        return SchannelCipherSuiteOrderEvidence(
            raw_value=raw_value,
            order_source="unknown",
            effective_order=(),
            state_reason="Cipher-suite order could not be safely read from the evidence source.",
            source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            completeness=completeness,
        )
    if completeness == "complete":
        if effective_order:
            return SchannelCipherSuiteOrderEvidence(
                raw_value=raw_value,
                order_source="default",
                effective_order=effective_order,
                state_reason=(
                    "Cipher-suite order override was absent in a complete collection, so the "
                    "reviewed exact-build default order was used."
                ),
                source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
                completeness=completeness,
                default_source=default_source,
                default_catalog_ref=default_catalog_ref,
            )
        return SchannelCipherSuiteOrderEvidence(
            raw_value=raw_value,
            order_source="unknown",
            effective_order=(),
            state_reason=(
                "Cipher-suite order override was absent in a complete collection, but the "
                "exact-build default order is not reviewed."
            ),
            source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            completeness=completeness,
        )
    return SchannelCipherSuiteOrderEvidence(
        raw_value=raw_value,
        order_source="unknown",
        effective_order=(),
        state_reason="Cipher-suite order override was absent in incomplete evidence.",
        source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
        completeness=completeness,
    )


def _parse_v2_dword_value(value: object, export_path: str, label: str) -> SchannelRegistryValue:
    if not isinstance(value, dict):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"TLS registry export {label} must be an object with present/value fields.",
            path=export_path,
        )
    present = value.get("present")
    if not isinstance(present, bool):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"TLS registry export {label} present field must be boolean.",
            path=export_path,
        )
    raw_value = value.get("value")
    if present:
        if not isinstance(raw_value, int):
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                f"TLS registry export {label} value must be an integer when present is true.",
                path=export_path,
            )
        return SchannelRegistryValue(
            present=True,
            value=raw_value,
            status="present",
            raw_value_repr=str(raw_value),
        )
    if "value" in value:
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"TLS registry export {label} cannot include value when present is false.",
            path=export_path,
        )
    return SchannelRegistryValue(present=False, status="absent")


def _parse_v2_string_list_value(
    value: object,
    export_path: str,
    label: str,
) -> SchannelRegistryStringList:
    if value is None:
        return SchannelRegistryStringList()
    if not isinstance(value, dict):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"TLS registry export {label} must be an object with present/value fields.",
            path=export_path,
        )
    present = value.get("present")
    if not isinstance(present, bool):
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"TLS registry export {label} present field must be boolean.",
            path=export_path,
        )
    raw_value = value.get("value")
    if present:
        if not isinstance(raw_value, list) or not all(
            isinstance(item, str) and item.strip() for item in raw_value
        ):
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                f"TLS registry export {label} value must be an array of strings when present is true.",
                path=export_path,
            )
        return SchannelRegistryStringList(
            present=True,
            value=tuple(item.strip() for item in raw_value),
            status="present",
            raw_value_repr=";".join(item.strip() for item in raw_value),
        )
    if "value" in value:
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"TLS registry export {label} cannot include value when present is false.",
            path=export_path,
        )
    return SchannelRegistryStringList(present=False, status="absent")


def _read_live_os_identity(
    reader: _RegistryReader,
    collection_issues: list[SchannelCollectionIssue],
) -> tuple[SchannelOSIdentity, CompletenessState]:
    product_name_read = _as_read_result(reader.query_value(_WINDOWS_VERSION_PATH, "ProductName"))
    version_read = _as_read_result(reader.query_value(_WINDOWS_VERSION_PATH, "CurrentVersion"))
    build_read = _as_read_result(reader.query_value(_WINDOWS_VERSION_PATH, "CurrentBuildNumber"))
    if build_read.status == "absent":
        build_read = _as_read_result(reader.query_value(_WINDOWS_VERSION_PATH, "CurrentBuild"))
    ubr_read = _as_read_result(reader.query_value(_WINDOWS_VERSION_PATH, "UBR"))

    product_name = _string_value(product_name_read)
    version = _string_value(version_read)
    build = _int_from_value(build_read.value) if build_read.status == "present" else None
    ubr = _int_from_value(ubr_read.value) if ubr_read.status == "present" else None

    completeness: CompletenessState = "complete"
    for label, read in {
        "product_name": product_name_read,
        "version": version_read,
        "build": build_read,
        "ubr": ubr_read,
    }.items():
        if read.status in {"access-denied", "error"}:
            completeness = "partial"
            collection_issues.append(
                SchannelCollectionIssue(
                    evidence_class="os_build",
                    code="iis_tls_registry_collection_issue",
                    message=f"Windows OS identity value {label!r} could not be read from the live registry.",
                    path=f"HKLM/{_WINDOWS_VERSION_PATH}",
                )
            )
        elif read.status == "present" and label in {"product_name", "version", "build"}:
            if (
                (label == "build" and build is None)
                or (label != "build" and not _string_value(read))
            ):
                completeness = "partial"
                collection_issues.append(
                    SchannelCollectionIssue(
                        evidence_class="os_build",
                        code="iis_tls_registry_collection_issue",
                        message=f"Windows OS identity value {label!r} was malformed in the live registry.",
                        path=f"HKLM/{_WINDOWS_VERSION_PATH}",
                    )
                )

    if not product_name or build is None:
        completeness = "unknown" if completeness == "complete" else completeness

    return (
        SchannelOSIdentity(
            product_name=product_name,
            version=version,
            build=build,
            ubr=ubr,
            architecture=platform.machine() or None,
        ),
        completeness,
    )


def _read_live_protocols(
    reader: _RegistryReader,
    os_identity: SchannelOSIdentity,
    collection_issues: list[SchannelCollectionIssue],
) -> tuple[list[SchannelProtocolEvidence], CompletenessState]:
    completeness: CompletenessState = "complete"
    reads: list[tuple[str, str, SchannelRegistryValue, SchannelRegistryValue]] = []
    for raw_name, normalized_name in _PROTOCOL_NAMES.items():
        server_path = f"{_SCHANNEL_BASE}\\Protocols\\{raw_name}\\Server"
        enabled_read = _as_read_result(reader.query_value(server_path, "Enabled"))
        disabled_by_default_read = _as_read_result(reader.query_value(server_path, "DisabledByDefault"))
        enabled = _dword_value_from_read(enabled_read)
        disabled_by_default = _dword_value_from_read(disabled_by_default_read)
        if enabled.status in {"access-denied", "malformed", "error"} or disabled_by_default.status in {
            "access-denied",
            "malformed",
            "error",
        }:
            completeness = "partial"
            collection_issues.append(
                SchannelCollectionIssue(
                    evidence_class="protocols",
                    code="iis_tls_registry_collection_issue",
                    message=(
                        f"SChannel protocol values for {raw_name!r} could not be read cleanly from the live registry."
                    ),
                    path=f"HKLM/{server_path}",
                )
            )
        reads.append(
            (
                raw_name,
                normalized_name,
                enabled,
                disabled_by_default,
            )
        )
    evidence = [
        _build_protocol_evidence(
            name=normalized_name,
            raw_name=raw_name,
            enabled=enabled,
            disabled_by_default=disabled_by_default,
            completeness=completeness,
            os_identity=os_identity,
        )
        for raw_name, normalized_name, enabled, disabled_by_default in reads
    ]
    return evidence, completeness


def _read_live_ciphers(
    reader: _RegistryReader,
    os_identity: SchannelOSIdentity,
    collection_issues: list[SchannelCollectionIssue],
) -> tuple[list[SchannelCipherEvidence], CompletenessState]:
    parent = f"{_SCHANNEL_BASE}\\Ciphers"
    subkeys_read = _as_read_result(reader.open_subkeys(parent))
    completeness: CompletenessState = "complete"
    discovered: list[str] = []
    if subkeys_read.status == "present":
        if isinstance(subkeys_read.value, list | tuple):
            discovered = [str(item) for item in subkeys_read.value]
        else:
            completeness = "partial"
            collection_issues.append(
                SchannelCollectionIssue(
                    evidence_class="ciphers",
                    code="iis_tls_registry_collection_issue",
                    message="SChannel cipher subkey enumeration returned malformed data.",
                    path=f"HKLM/{parent}",
                )
            )
    elif subkeys_read.status in {"access-denied", "error", "malformed"}:
        completeness = "partial"
        collection_issues.append(
            SchannelCollectionIssue(
                evidence_class="ciphers",
                code="iis_tls_registry_collection_issue",
                message="SChannel cipher subkeys could not be read from the live registry.",
                path=f"HKLM/{parent}",
            )
        )
    names: list[str] = []
    seen: set[str] = set()
    for raw_name in [*discovered, *_SYNTHETIC_CIPHERS]:
        key = _normalize_cipher_key(raw_name)
        if key in seen:
            continue
        seen.add(key)
        names.append(raw_name)

    reads: list[tuple[str, SchannelRegistryValue]] = []
    for raw_name in names:
        path = f"{parent}\\{raw_name}"
        enabled = (
            _dword_value_from_read(_as_read_result(reader.query_value(path, "Enabled")))
            if raw_name in discovered
            else SchannelRegistryValue()
        )
        if enabled.status in {"access-denied", "error", "malformed"}:
            completeness = "partial"
            collection_issues.append(
                SchannelCollectionIssue(
                    evidence_class="ciphers",
                    code="iis_tls_registry_collection_issue",
                    message=f"SChannel cipher value for {raw_name!r} could not be read cleanly from the live registry.",
                    path=f"HKLM/{path}",
                )
            )
        reads.append((raw_name, enabled))

    evidence = [
        _build_cipher_evidence(
            name=raw_name.strip(),
            raw_name=raw_name.strip(),
            enabled=enabled,
            completeness=completeness,
            os_identity=os_identity,
        )
        for raw_name, enabled in reads
    ]
    return evidence, completeness


def _read_live_cipher_suite_order(
    reader: _RegistryReader,
    os_identity: SchannelOSIdentity,
    collection_issues: list[SchannelCollectionIssue],
) -> tuple[SchannelCipherSuiteOrderEvidence, CompletenessState]:
    read = _as_read_result(reader.query_value(_CIPHER_SUITE_ORDER_PATH, "Functions"))
    raw_value = _string_list_from_read(read)
    completeness: CompletenessState = "complete"
    if raw_value.status in {"access-denied", "error", "malformed"}:
        completeness = "partial"
        collection_issues.append(
            SchannelCollectionIssue(
                evidence_class="cipher_suite_order",
                code="iis_tls_registry_collection_issue",
                message="SChannel cipher-suite order could not be read cleanly from the live registry.",
                path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            )
        )
    order = _parse_live_cipher_suite_order(raw_value, completeness, os_identity)
    return order, completeness


def _parse_live_cipher_suite_order(
    raw_value: SchannelRegistryStringList,
    completeness: CompletenessState,
    os_identity: SchannelOSIdentity,
) -> SchannelCipherSuiteOrderEvidence:
    effective_order, default_source, default_catalog_ref = cipher_suite_order_default(os_identity)
    if raw_value.present and raw_value.status == "present":
        return SchannelCipherSuiteOrderEvidence(
            raw_value=raw_value,
            order_source="explicit",
            effective_order=raw_value.value,
            state_reason="Cipher-suite order was explicitly configured in the live registry.",
            source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            completeness=completeness,
        )
    if raw_value.status in {"access-denied", "error", "malformed"}:
        return SchannelCipherSuiteOrderEvidence(
            raw_value=raw_value,
            order_source="unknown",
            effective_order=(),
            state_reason="Cipher-suite order could not be safely read from the live registry.",
            source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            completeness=completeness,
        )
    if completeness == "complete":
        if effective_order:
            return SchannelCipherSuiteOrderEvidence(
                raw_value=raw_value,
                order_source="default",
                effective_order=effective_order,
                state_reason=(
                    "Cipher-suite order override was absent in a complete collection, so the "
                    "reviewed exact-build default order was used."
                ),
                source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
                completeness=completeness,
                default_source=default_source,
                default_catalog_ref=default_catalog_ref,
            )
        return SchannelCipherSuiteOrderEvidence(
            raw_value=raw_value,
            order_source="unknown",
            effective_order=(),
            state_reason=(
                "Cipher-suite order override was absent in a complete collection, but the "
                "exact-build default order is not reviewed."
            ),
            source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            completeness=completeness,
        )
    return SchannelCipherSuiteOrderEvidence(
        raw_value=raw_value,
        order_source="unknown",
        effective_order=(),
        state_reason="Cipher-suite order override was absent in incomplete evidence.",
        source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
        completeness=completeness,
    )


class _WinregReader:
    """Concrete ``winreg``-backed reader, imported lazily for portability."""

    def __init__(self) -> None:
        import winreg  # noqa: PLC0415 - Windows-only stdlib import.

        self._winreg = winreg
        self._root = winreg.HKEY_LOCAL_MACHINE

    def open_subkeys(self, parent: str) -> _ReadResult:
        try:
            handle = self._winreg.OpenKey(self._root, parent)
        except OSError as exc:
            return _status_from_os_error(exc)
        names: list[str] = []
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
        return _ReadResult("present", value=names)

    def query_value(self, parent: str, value_name: str) -> _ReadResult:
        try:
            handle = self._winreg.OpenKey(self._root, parent)
        except OSError as exc:
            return _status_from_os_error(exc)
        try:
            try:
                value, _kind = self._winreg.QueryValueEx(handle, value_name)
            except OSError as exc:
                return _status_from_os_error(exc)
        finally:
            handle.Close()
        return _ReadResult("present", value=value)


def _build_protocol_evidence(
    *,
    name: str,
    raw_name: str,
    enabled: SchannelRegistryValue,
    disabled_by_default: SchannelRegistryValue,
    completeness: CompletenessState,
    os_identity: SchannelOSIdentity,
) -> SchannelProtocolEvidence:
    default_effective_state, default_source, default_catalog_ref = protocol_default_state(
        os_identity,
        name,
    )
    state, effective_state, reason = resolve_schannel_state(
        enabled=enabled,
        disabled_by_default=disabled_by_default,
        completeness=completeness,
        default_effective_state=default_effective_state,
    )
    return SchannelProtocolEvidence(
        name=name,
        raw_name=raw_name,
        server=SchannelProtocolRegistryEvidence(
            enabled=enabled,
            disabled_by_default=disabled_by_default,
        ),
        state=state,
        effective_state=effective_state,
        state_reason=reason,
        source_path=f"{_SCHANNEL_SOURCE_PATH}/Protocols/{raw_name}/Server",
        completeness=completeness,
        default_effective_state=default_effective_state if state == "default" else "unknown",
        default_source=default_source if state == "default" else None,
        default_catalog_ref=default_catalog_ref if state == "default" else None,
    )


def _build_cipher_evidence(
    *,
    name: str,
    raw_name: str,
    enabled: SchannelRegistryValue,
    completeness: CompletenessState,
    os_identity: SchannelOSIdentity,
) -> SchannelCipherEvidence:
    default_effective_state, default_source, default_catalog_ref = cipher_default_state(
        os_identity,
        name,
    )
    state, effective_state, reason = resolve_schannel_state(
        enabled=enabled,
        disabled_by_default=None,
        completeness=completeness,
        default_effective_state=default_effective_state,
    )
    return SchannelCipherEvidence(
        name=name,
        raw_name=raw_name,
        enabled=enabled,
        state=state,
        effective_state=effective_state,
        state_reason=reason,
        source_path=f"{_SCHANNEL_SOURCE_PATH}/Ciphers/{raw_name}",
        completeness=completeness,
        default_effective_state=default_effective_state if state == "default" else "unknown",
        default_source=default_source if state == "default" else None,
        default_catalog_ref=default_catalog_ref if state == "default" else None,
    )


def _resolve_protocol_state(
    *,
    enabled: SchannelRegistryValue,
    disabled_by_default: SchannelRegistryValue,
    completeness: CompletenessState,
    default_effective_state: EffectiveState,
) -> tuple[SchannelState, EffectiveState, str]:
    if enabled.status in {"access-denied", "malformed", "error"}:
        return "unknown", "unknown", "Enabled value could not be safely read."
    if disabled_by_default.status in {"access-denied", "malformed", "error"}:
        return "unknown", "unknown", "DisabledByDefault value could not be safely read."
    if enabled.present and enabled.value is not None:
        if enabled.value != 0 and disabled_by_default.present and disabled_by_default.value == 0:
            return "enabled", "enabled", "Enabled is nonzero and DisabledByDefault is 0."
        if enabled.value == 0 and (
            (disabled_by_default.present and disabled_by_default.value in {0, 1})
            or not disabled_by_default.present
        ):
            return "disabled", "disabled", "Enabled is 0."
        if enabled.value != 0 and disabled_by_default.present and disabled_by_default.value == 1:
            return "unknown", "unknown", "Enabled is nonzero while DisabledByDefault is 1."
        return "unknown", "unknown", "Protocol registry values are contradictory or incomplete."
    if not enabled.present and not disabled_by_default.present:
        if completeness == "complete":
            if default_effective_state == "unknown":
                return (
                    "default",
                    "unknown",
                    "Registry override is absent in a complete collection, but the exact-build default is not reviewed.",
                )
            return (
                "default",
                default_effective_state,
                "Registry override is absent in a complete collection and exact-build defaults were applied.",
            )
        return "unknown", "unknown", "Registry override is absent in incomplete evidence."
    return "unknown", "unknown", "Protocol registry values are contradictory or incomplete."


def _resolve_cipher_state(
    *,
    enabled: SchannelRegistryValue,
    completeness: CompletenessState,
    default_effective_state: EffectiveState,
) -> tuple[SchannelState, EffectiveState, str]:
    if enabled.status in {"access-denied", "malformed", "error"}:
        return "unknown", "unknown", "Enabled value could not be safely read."
    if enabled.present and enabled.value is not None:
        if enabled.value != 0:
            return "enabled", "enabled", "Enabled is nonzero."
        return "disabled", "disabled", "Enabled is 0."
    if completeness == "complete":
        if default_effective_state == "unknown":
            return (
                "default",
                "unknown",
                "Registry override is absent in a complete collection, but the exact-build default is not reviewed.",
            )
        return (
            "default",
            default_effective_state,
            "Registry override is absent in a complete collection and exact-build defaults were applied.",
        )
    return "unknown", "unknown", "Registry override is absent in incomplete evidence."


def _legacy_wrapper_to_evidence(registry_tls: IISRegistryTLS) -> IISSchannelEvidence:
    protocols = [
        SchannelProtocolEvidence(
            name=protocol_name,
            raw_name=protocol_name,
            server=SchannelProtocolRegistryEvidence(),
            state="enabled" if registry_tls.protocols_enabled and protocol_name in registry_tls.protocols_enabled else "unknown",
            effective_state="enabled" if registry_tls.protocols_enabled and protocol_name in registry_tls.protocols_enabled else "unknown",
            state_reason=(
                "Legacy compatibility wrapper lists this protocol as enabled."
                if registry_tls.protocols_enabled and protocol_name in registry_tls.protocols_enabled
                else "Legacy compatibility wrapper does not prove this protocol state."
            ),
            source_path=f"{_SCHANNEL_SOURCE_PATH}/Protocols/{protocol_name}/Server",
            completeness="partial",
        )
        for protocol_name in _KNOWN_PROTOCOLS
    ]

    cipher_names: list[str] = []
    seen: set[str] = set()
    for raw_name in [*(registry_tls.ciphers_enabled or []), *_SYNTHETIC_CIPHERS]:
        key = _normalize_cipher_key(raw_name)
        if key in seen:
            continue
        seen.add(key)
        cipher_names.append(raw_name)
    ciphers = [
        SchannelCipherEvidence(
            name=name,
            raw_name=name,
            enabled=SchannelRegistryValue(
                present=True,
                value=1,
                status="present",
            )
            if registry_tls.ciphers_enabled and name in registry_tls.ciphers_enabled
            else SchannelRegistryValue(),
            state="enabled" if registry_tls.ciphers_enabled and name in registry_tls.ciphers_enabled else "unknown",
            effective_state="enabled" if registry_tls.ciphers_enabled and name in registry_tls.ciphers_enabled else "unknown",
            state_reason=(
                "Legacy compatibility wrapper lists this cipher as enabled."
                if registry_tls.ciphers_enabled and name in registry_tls.ciphers_enabled
                else "Legacy compatibility wrapper does not prove this cipher state."
            ),
            source_path=f"{_SCHANNEL_SOURCE_PATH}/Ciphers/{name}",
            completeness="partial",
        )
        for name in cipher_names
    ]
    order = (
        SchannelCipherSuiteOrderEvidence(
            raw_value=SchannelRegistryStringList(
                present=True,
                value=tuple(registry_tls.cipher_suite_order),
                status="present",
            ),
            order_source="explicit",
            effective_order=tuple(registry_tls.cipher_suite_order),
            state_reason="Legacy compatibility wrapper carries an explicit cipher-suite order.",
            source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            completeness="complete",
        )
        if registry_tls.cipher_suite_order is not None
        else SchannelCipherSuiteOrderEvidence(
            raw_value=SchannelRegistryStringList(),
            order_source="unknown",
            effective_order=(),
            state_reason="Legacy compatibility wrapper does not prove cipher-suite order.",
            source_path=f"HKLM/{_CIPHER_SUITE_ORDER_PATH}",
            completeness="unknown",
        )
    )
    return IISSchannelEvidence(
        host=registry_tls.host,
        captured_at=datetime.now(UTC),
        os=SchannelOSIdentity(),
        completeness=SchannelCompleteness(
            os_build="unknown",
            protocols="partial" if registry_tls.protocols_enabled is not None else "unknown",
            ciphers="partial" if registry_tls.ciphers_enabled is not None else "unknown",
            cipher_suite_order="complete" if registry_tls.cipher_suite_order is not None else "unknown",
        ),
        schannel=SchannelEvidenceData(
            protocols=tuple(protocols),
            ciphers=tuple(ciphers),
            cipher_suite_order=order,
        ),
        source_kind="export" if registry_tls.source_kind == "export" else "live",
        source_label=registry_tls.source_label,
        input_schema_version=1,
        adapted_to_v2=True,
    )


def _parse_v1_protocols(value: object) -> set[str]:
    if not isinstance(value, dict):
        return set()
    enabled: set[str] = set()
    for raw_name, entry in value.items():
        if not isinstance(raw_name, str) or not isinstance(entry, dict):
            continue
        normalized = _normalize_protocol_name(raw_name)
        if normalized is None:
            continue
        if _protocol_effectively_enabled(
            entry.get("server_enabled"),
            entry.get("server_disabled_by_default"),
        ):
            enabled.add(normalized)
    return enabled


def _parse_v1_ciphers(value: object) -> set[str]:
    if not isinstance(value, dict):
        return set()
    enabled: set[str] = set()
    for raw_name, entry in value.items():
        if not isinstance(raw_name, str) or not isinstance(entry, dict):
            continue
        if _is_truthy_dword(entry.get("enabled")):
            enabled.add(raw_name.strip())
    return enabled


def _parse_v1_cipher_suite_order(schannel: dict[str, object]) -> list[str] | None:
    value = schannel.get("cipher_suite_order")
    if value is None:
        value = schannel.get("cipher_suites")
    return _parse_cipher_suite_order_value(value)


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


def _protocol_effectively_enabled(server_enabled: object, server_disabled_by_default: object) -> bool:
    if not isinstance(server_enabled, int) or not isinstance(server_disabled_by_default, int):
        return False
    return server_enabled != 0 and server_disabled_by_default == 0


def _is_truthy_dword(value: object) -> bool:
    return isinstance(value, int) and value != 0


def _as_read_result(value: object) -> _ReadResult:
    if isinstance(value, _ReadResult):
        return value
    if value is None:
        return _ReadResult("absent")
    return _ReadResult("present", value=value)


def _dword_value_from_read(read: _ReadResult) -> SchannelRegistryValue:
    if read.status == "present":
        if isinstance(read.value, int):
            return SchannelRegistryValue(
                present=True,
                value=read.value,
                status="present",
                raw_value_repr=str(read.value),
            )
        return SchannelRegistryValue(
            present=True,
            status="malformed",
            raw_value_repr=repr(read.value),
        )
    return SchannelRegistryValue(
        present=False,
        status=read.status,
        raw_value_repr=repr(read.value) if read.value is not None else None,
    )


def _string_list_from_read(read: _ReadResult) -> SchannelRegistryStringList:
    if read.status == "present":
        parsed = _parse_cipher_suite_order_value(read.value)
        if parsed is None:
            return SchannelRegistryStringList(
                present=True,
                status="malformed",
                raw_value_repr=repr(read.value),
            )
        return SchannelRegistryStringList(
            present=True,
            value=tuple(parsed),
            status="present",
            raw_value_repr=repr(read.value),
        )
    return SchannelRegistryStringList(
        present=False,
        status=read.status,
        raw_value_repr=repr(read.value) if read.value is not None else None,
    )


def _status_from_os_error(exc: OSError) -> _ReadResult:
    winerror = getattr(exc, "winerror", None)
    if winerror in {2, 3}:
        return _ReadResult("absent")
    if winerror == 5:
        return _ReadResult("access-denied", error=str(exc))
    return _ReadResult("error", error=str(exc))


def _normalize_protocol_name(raw_name: str) -> str:
    stripped = raw_name.strip()
    return _PROTOCOL_NAMES.get(stripped, stripped)


def _normalize_cipher_key(raw_name: str) -> str:
    return " ".join(raw_name.strip().lower().split())


def _string_value(read: _ReadResult) -> str | None:
    if read.status != "present" or not isinstance(read.value, str):
        return None
    return read.value.strip() or None


def _int_from_value(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _validate_collection_issue_completeness(
    issues: list[SchannelCollectionIssue],
    completeness: SchannelCompleteness,
    export_path: str,
) -> None:
    for issue in issues:
        if issue.evidence_class == "protocols" and completeness.protocols == "complete":
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                "TLS registry export cannot mark protocols complete while reporting protocol collection issues.",
                path=export_path,
            )
        if issue.evidence_class == "ciphers" and completeness.ciphers == "complete":
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                "TLS registry export cannot mark ciphers complete while reporting cipher collection issues.",
                path=export_path,
            )
        if issue.evidence_class == "cipher_suite_order" and completeness.cipher_suite_order == "complete":
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                "TLS registry export cannot mark cipher_suite_order complete while reporting order collection issues.",
                path=export_path,
            )
        if issue.evidence_class == "os_build" and completeness.os_build == "complete":
            raise SchannelEvidenceLoadError(
                "iis_tls_registry_export_error",
                "TLS registry export cannot mark os_build complete while reporting OS identity issues.",
                path=export_path,
            )


def _required_string(value: object, export_path: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchannelEvidenceLoadError(
            "iis_tls_registry_export_error",
            f"TLS registry export {label} must be a non-empty string.",
            path=export_path,
        )
    return value.strip()


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _export_issue(exc: SchannelEvidenceLoadError) -> AnalysisIssue:
    return AnalysisIssue(
        code=exc.code,
        level="error",
        message=str(exc),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=exc.path or "<unknown>",
        ),
    )


__all__ = [
    "IISRegistryTLS",
    "SchannelEvidenceLoadError",
    "coerce_schannel_evidence",
    "load_registry_export",
    "load_schannel_export",
    "read_live_registry",
    "read_live_schannel",
    "resolve_registry_tls",
    "resolve_schannel_evidence",
    "resolve_schannel_state",
]
