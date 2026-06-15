"""IIS SChannel rules backed by canonical v2 registry evidence semantics."""

from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.registry import IISRegistryTLS, coerce_schannel_evidence
from webconf_audit.local.iis.schannel_models import (
    IISSchannelEvidence,
    SchannelCipherEvidence,
    SchannelProtocolEvidence,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021, rfc

TLS12_RULE_ID = "iis.schannel_tls12_not_enabled"
WEAK_PROTOCOL_RULE_ID = "iis.schannel_weak_protocol_enabled"
AES128_RULE_ID = "iis.schannel_aes128_enabled"
AES256_RULE_ID = "iis.schannel_aes256_not_enabled"
CIPHER_ORDER_RULE_ID = "iis.schannel_cipher_suite_order_not_preferred"

_WEAK_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})
_AES128_CIPHER = "aes 128/128"
_AES256_CIPHER = "aes 256/256"

_CIS_CIPHER_SUITE_PREFIX = (
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
)


@rule(
    rule_id=TLS12_RULE_ID,
    title="IIS SChannel TLS 1.2 is not enabled",
    severity="medium",
    description="Windows SChannel registry data does not show TLS 1.2 enabled for IIS.",
    recommendation="Enable TLS 1.2 for the SChannel Server protocol.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="mixed",
    order=534,
)
def find_schannel_tls12_not_enabled(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISSchannelEvidence | IISRegistryTLS | None = None,
) -> list[Finding]:
    evidence = coerce_schannel_evidence(registry_tls)
    if evidence is None:
        return []
    protocol = evidence.protocol("TLSv1.2")
    if protocol is None or protocol.effective_state == "unknown":
        return []
    if protocol.effective_state == "enabled":
        return []
    return [
        _finding(
            evidence,
            rule_id=TLS12_RULE_ID,
            title="IIS SChannel TLS 1.2 is not enabled",
            description=(
                "Windows SChannel evidence shows TLS 1.2 is not effectively enabled for IIS. "
                f"{_protocol_summary(protocol)}."
            ),
            recommendation="Set the SChannel TLS 1.2 Server Enabled value to 1 and DisabledByDefault to 0.",
        )
    ]


@rule(
    rule_id=WEAK_PROTOCOL_RULE_ID,
    title="IIS SChannel weak TLS/SSL protocol is enabled",
    severity="medium",
    description="Windows SChannel registry data shows weak server TLS/SSL protocols enabled.",
    recommendation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 for SChannel Server protocols.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="mixed",
    standards=(
        cwe(327),
        owasp_top10_2021("A02:2021"),
        asvs_5("12.1.1"),
        rfc(
            8996,
            coverage="partial",
            note="Flags RFC 8996-deprecated TLS 1.0 / 1.1 alongside adjacent legacy SSLv2/SSLv3 posture.",
        ),
    ),
    order=535,
)
def find_schannel_weak_protocol_enabled(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISSchannelEvidence | IISRegistryTLS | None = None,
) -> list[Finding]:
    evidence = coerce_schannel_evidence(registry_tls)
    if evidence is None:
        return []
    weak_protocols = [
        protocol
        for protocol in evidence.schannel.protocols
        if protocol.name in _WEAK_PROTOCOLS and protocol.effective_state == "enabled"
    ]
    if not weak_protocols:
        return []
    return [
        _finding(
            evidence,
            rule_id=WEAK_PROTOCOL_RULE_ID,
            title="IIS SChannel weak TLS/SSL protocol is enabled",
            description=(
                "Windows SChannel evidence shows weak server protocols enabled for IIS: "
                + ", ".join(_protocol_observation(protocol) for protocol in weak_protocols)
                + "."
            ),
            recommendation=(
                "Set the SChannel Server Enabled value to 0 for SSL 2.0, "
                "SSL 3.0, TLS 1.0, and TLS 1.1."
            ),
        )
    ]


@rule(
    rule_id=AES128_RULE_ID,
    title="IIS SChannel AES 128/128 cipher is enabled",
    severity="medium",
    description="Windows SChannel registry data shows the AES 128/128 cipher enabled.",
    recommendation="Disable the SChannel AES 128/128 cipher when client compatibility allows.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="mixed",
    order=536,
)
def find_schannel_aes128_enabled(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISSchannelEvidence | IISRegistryTLS | None = None,
) -> list[Finding]:
    evidence = coerce_schannel_evidence(registry_tls)
    if evidence is None:
        return []
    cipher = _cipher_by_key(evidence, _AES128_CIPHER)
    if cipher is None or cipher.effective_state != "enabled":
        return []
    return [
        _finding(
            evidence,
            rule_id=AES128_RULE_ID,
            title="IIS SChannel AES 128/128 cipher is enabled",
            description=(
                "Windows SChannel evidence shows AES 128/128 is effectively enabled, "
                f"while the CIS IIS benchmark recommends disabling it. {_cipher_summary(cipher)}."
            ),
            recommendation="Set the SChannel Ciphers\\AES 128/128 Enabled value to 0.",
        )
    ]


@rule(
    rule_id=AES256_RULE_ID,
    title="IIS SChannel AES 256/256 cipher is not enabled",
    severity="medium",
    description="Windows SChannel registry data does not show the AES 256/256 cipher enabled.",
    recommendation="Enable the SChannel AES 256/256 cipher.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="mixed",
    order=537,
)
def find_schannel_aes256_not_enabled(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISSchannelEvidence | IISRegistryTLS | None = None,
) -> list[Finding]:
    evidence = coerce_schannel_evidence(registry_tls)
    if evidence is None:
        return []
    cipher = _cipher_by_key(evidence, _AES256_CIPHER)
    if cipher is None or cipher.effective_state == "unknown":
        return []
    if cipher.effective_state == "enabled":
        return []
    return [
        _finding(
            evidence,
            rule_id=AES256_RULE_ID,
            title="IIS SChannel AES 256/256 cipher is not enabled",
            description=(
                "Windows SChannel evidence shows AES 256/256 is not effectively enabled. "
                f"{_cipher_summary(cipher)}."
            ),
            recommendation="Set the SChannel Ciphers\\AES 256/256 Enabled value to 1.",
        )
    ]


@rule(
    rule_id=CIPHER_ORDER_RULE_ID,
    title="IIS SChannel cipher suite order is not CIS preferred",
    severity="medium",
    description="Windows SChannel cipher suite order does not start with the CIS IIS preferred order.",
    recommendation="Configure the SSL cipher suite Functions policy with the CIS IIS preferred order.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="mixed",
    order=538,
)
def find_schannel_cipher_suite_order_not_preferred(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISSchannelEvidence | IISRegistryTLS | None = None,
) -> list[Finding]:
    evidence = coerce_schannel_evidence(registry_tls)
    if evidence is None:
        return []
    order = evidence.schannel.cipher_suite_order
    if order.order_source == "unknown":
        return []
    effective_order = list(order.effective_order)
    if _cipher_suite_order_has_cis_prefix(effective_order):
        return []
    first_suite = effective_order[0] if effective_order else "none"
    source_phrase = (
        "Windows default order"
        if order.order_source == "default"
        else "Configured cipher-suite order"
    )
    return [
        _finding(
            evidence,
            rule_id=CIPHER_ORDER_RULE_ID,
            title="IIS SChannel cipher suite order is not CIS preferred",
            description=(
                f"{source_phrase} does not start with the CIS IIS preferred order. "
                f"First effective suite: {first_suite}."
            ),
            recommendation=(
                "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002:"
                "Functions to the CIS IIS preferred TLS cipher suite order."
            ),
        )
    ]


def _cipher_by_key(
    evidence: IISSchannelEvidence,
    normalized_cipher: str,
) -> SchannelCipherEvidence | None:
    return next(
        (
            cipher
            for cipher in evidence.schannel.ciphers
            if _normalize_cipher_name(cipher.name) == normalized_cipher
        ),
        None,
    )


def _normalize_cipher_name(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _cipher_suite_order_has_cis_prefix(cipher_suite_order: list[str]) -> bool:
    normalized = [_normalize_suite_name(suite) for suite in cipher_suite_order]
    required = [_normalize_suite_name(suite) for suite in _CIS_CIPHER_SUITE_PREFIX]
    return normalized[: len(required)] == required


def _normalize_suite_name(value: str) -> str:
    return value.strip().upper()


def _protocol_observation(protocol: SchannelProtocolEvidence) -> str:
    if protocol.state == "default":
        return f"{protocol.raw_name} (default resolves to {protocol.effective_state})"
    return f"{protocol.raw_name} ({protocol.state})"


def _protocol_summary(protocol: SchannelProtocolEvidence) -> str:
    if protocol.state == "default":
        if protocol.effective_state == "unknown":
            return (
                "The protocol uses OS defaults, but the exact build was not reviewed for default resolution."
            )
        return f"The protocol uses OS defaults, which resolve to {protocol.effective_state}."
    return protocol.state_reason


def _cipher_summary(cipher: SchannelCipherEvidence) -> str:
    if cipher.state == "default":
        if cipher.effective_state == "unknown":
            return (
                "The cipher uses OS defaults, but the exact build was not reviewed for default resolution."
            )
        return f"The cipher uses OS defaults, which resolve to {cipher.effective_state}."
    return cipher.state_reason


def _finding(
    evidence: IISSchannelEvidence,
    *,
    rule_id: str,
    title: str,
    description: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity="medium",
        description=description,
        recommendation=recommendation,
        location=SourceLocation(
            mode="local",
            kind="tls",
            file_path=evidence.source_file_path,
            details=evidence.source_details,
        ),
    )


__all__ = [
    "find_schannel_aes128_enabled",
    "find_schannel_aes256_not_enabled",
    "find_schannel_cipher_suite_order_not_preferred",
    "find_schannel_tls12_not_enabled",
    "find_schannel_weak_protocol_enabled",
]
