"""Canonical IIS SChannel evidence models and helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SchannelState = Literal["enabled", "disabled", "default", "unknown"]
CompletenessState = Literal["complete", "partial", "unknown"]
EffectiveState = Literal["enabled", "disabled", "unknown"]
CipherSuiteOrderSource = Literal["explicit", "default", "unknown"]
SchannelSourceKind = Literal["live", "export"]
SchannelReadStatus = Literal["present", "absent", "access-denied", "malformed", "error"]
SchannelCollectionClass = Literal[
    "os_build",
    "protocols",
    "ciphers",
    "cipher_suite_order",
    "adapter",
]

_SCHANNEL_KIND = "iis-schannel-evidence"
_LIVE_SOURCE_LABEL = "live SChannel registry"
_SCHANNEL_SOURCE_PATH = "HKLM/SYSTEM/CurrentControlSet/Control/SecurityProviders/SCHANNEL"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SchannelCollectionIssue(_StrictModel):
    """A class-scoped collection or compatibility warning."""

    evidence_class: SchannelCollectionClass
    code: str
    message: str
    path: str | None = None
    severity: Literal["warning", "error"] = "warning"


class SchannelRegistryValue(_StrictModel):
    """Observed registry DWORD state with structured read status."""

    present: bool = False
    value: int | None = None
    status: SchannelReadStatus = "absent"
    raw_value_repr: str | None = None


class SchannelRegistryStringList(_StrictModel):
    """Observed multi-string/string state for cipher-suite order."""

    present: bool = False
    value: tuple[str, ...] = Field(default=(), max_length=256)
    status: SchannelReadStatus = "absent"
    raw_value_repr: str | None = None


class SchannelOSIdentity(_StrictModel):
    """OS identity required for exact-build default resolution."""

    product_name: str | None = None
    version: str | None = None
    build: int | None = None
    ubr: int | None = None
    architecture: str | None = None


class SchannelCompleteness(_StrictModel):
    """Per-class completeness declarations for SChannel evidence."""

    os_build: CompletenessState = "unknown"
    protocols: CompletenessState = "unknown"
    ciphers: CompletenessState = "unknown"
    cipher_suite_order: CompletenessState = "unknown"


class SchannelProtocolRegistryEvidence(_StrictModel):
    """Raw registry values used to derive one server protocol state."""

    enabled: SchannelRegistryValue = Field(default_factory=SchannelRegistryValue)
    disabled_by_default: SchannelRegistryValue = Field(default_factory=SchannelRegistryValue)


class SchannelProtocolEvidence(_StrictModel):
    """Canonical protocol evidence after state resolution."""

    name: str
    raw_name: str
    server: SchannelProtocolRegistryEvidence
    state: SchannelState
    effective_state: EffectiveState
    state_reason: str
    source_path: str
    completeness: CompletenessState
    default_effective_state: EffectiveState = "unknown"
    default_source: str | None = None
    default_catalog_ref: str | None = None


class SchannelCipherEvidence(_StrictModel):
    """Canonical cipher evidence after state resolution."""

    name: str
    raw_name: str
    enabled: SchannelRegistryValue = Field(default_factory=SchannelRegistryValue)
    state: SchannelState
    effective_state: EffectiveState
    state_reason: str
    source_path: str
    completeness: CompletenessState
    default_effective_state: EffectiveState = "unknown"
    default_source: str | None = None
    default_catalog_ref: str | None = None


class SchannelCipherSuiteOrderEvidence(_StrictModel):
    """Canonical cipher-suite order evidence."""

    raw_value: SchannelRegistryStringList = Field(default_factory=SchannelRegistryStringList)
    order_source: CipherSuiteOrderSource = "unknown"
    effective_order: tuple[str, ...] = Field(default=(), max_length=256)
    state_reason: str = "Cipher-suite order was not collected."
    source_path: str
    completeness: CompletenessState
    default_source: str | None = None
    default_catalog_ref: str | None = None


class SchannelEvidenceData(_StrictModel):
    """Grouped canonical SChannel evidence classes."""

    protocols: tuple[SchannelProtocolEvidence, ...] = Field(default=(), max_length=128)
    ciphers: tuple[SchannelCipherEvidence, ...] = Field(default=(), max_length=256)
    cipher_suite_order: SchannelCipherSuiteOrderEvidence


class SchannelDefaultCatalogEntry(_StrictModel):
    """Exact-build reviewed defaults used for safe default resolution."""

    catalog_id: str
    product_match: str
    build_min: int
    build_max: int
    source_url: str
    reviewed_on: str
    protocol_defaults: dict[str, EffectiveState] = Field(default_factory=dict)
    cipher_defaults: dict[str, EffectiveState] = Field(default_factory=dict)
    cipher_suite_order: tuple[str, ...] = Field(default=(), max_length=256)


class IISSchannelEvidence(_StrictModel):
    """Versioned canonical IIS SChannel evidence."""

    schema_version: Literal[2] = 2
    kind: Literal[_SCHANNEL_KIND] = _SCHANNEL_KIND
    host: str | None = None
    captured_at: datetime
    os: SchannelOSIdentity = Field(default_factory=SchannelOSIdentity)
    completeness: SchannelCompleteness = Field(default_factory=SchannelCompleteness)
    schannel: SchannelEvidenceData
    collection_issues: tuple[SchannelCollectionIssue, ...] = Field(default=(), max_length=256)
    source_kind: SchannelSourceKind = "live"
    source_label: str = _LIVE_SOURCE_LABEL
    input_schema_version: Literal[1, 2] = 2
    adapted_to_v2: bool = False

    @property
    def has_data(self) -> bool:
        return bool(
            self.schannel.protocols
            or self.schannel.ciphers
            or self.schannel.cipher_suite_order.raw_value.present
            or self.schannel.cipher_suite_order.order_source != "unknown"
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

    def source_ref(self):
        from webconf_audit.local.normalized import SourceRef

        return SourceRef(
            server_type="iis",
            file_path=self.source_file_path,
            details=self.source_details,
        )

    def source_issue(self):
        from webconf_audit.models import AnalysisIssue, SourceLocation

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
                "schema_version": self.schema_version,
                "input_schema_version": self.input_schema_version,
                "adapted_to_v2": self.adapted_to_v2,
                "protocols_known": self.completeness.protocols == "complete",
                "ciphers_known": self.completeness.ciphers == "complete",
                "cipher_suite_order_known": self.completeness.cipher_suite_order == "complete",
            },
        )

    def issue_records(self):
        from webconf_audit.models import AnalysisIssue, SourceLocation

        issues: list[AnalysisIssue] = []
        for issue in self.collection_issues:
            location = SourceLocation(
                mode="local",
                kind="tls",
                file_path=self.source_file_path,
                details=issue.path or self.source_details,
            )
            issues.append(
                AnalysisIssue(
                    code=issue.code,
                    level=issue.severity,
                    message=issue.message,
                    location=location,
                )
            )
        return issues

    def protocol(self, name: str) -> SchannelProtocolEvidence | None:
        return next((entry for entry in self.schannel.protocols if entry.name == name), None)

    def cipher(self, name: str) -> SchannelCipherEvidence | None:
        return next((entry for entry in self.schannel.ciphers if entry.name == name), None)

    def enabled_protocols(self) -> list[str]:
        return [
            entry.name
            for entry in self.schannel.protocols
            if entry.effective_state == "enabled"
        ]

    def enabled_ciphers(self) -> list[str]:
        return [
            entry.name
            for entry in self.schannel.ciphers
            if entry.effective_state == "enabled"
        ]

    def effective_cipher_suite_order(self) -> list[str] | None:
        if self.schannel.cipher_suite_order.order_source == "unknown":
            return None
        return list(self.schannel.cipher_suite_order.effective_order)


__all__ = [
    "CipherSuiteOrderSource",
    "CompletenessState",
    "EffectiveState",
    "IISSchannelEvidence",
    "SchannelCipherEvidence",
    "SchannelCipherSuiteOrderEvidence",
    "SchannelCollectionIssue",
    "SchannelCompleteness",
    "SchannelDefaultCatalogEntry",
    "SchannelEvidenceData",
    "SchannelOSIdentity",
    "SchannelProtocolEvidence",
    "SchannelProtocolRegistryEvidence",
    "SchannelReadStatus",
    "SchannelRegistryStringList",
    "SchannelRegistryValue",
    "SchannelSourceKind",
    "SchannelState",
]
