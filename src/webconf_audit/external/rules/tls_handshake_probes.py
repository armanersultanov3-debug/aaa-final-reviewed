"""Implements rules: ``external.tls_secure_renegotiation_not_observed``, ``external.tls_negotiated_compression``, ``external.tls_aead_cipher_not_negotiated``.

Location: ``src/webconf_audit/external/rules/tls_handshake_probes.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.rules._helpers import _successful_attempts_for_scheme
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, nist_sp, owasp_top10_2021

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt


_TLS12_AND_EARLIER = frozenset({"TLSv1", "TLSv1.1", "TLSv1.2"})


def _tls12_or_earlier(protocol_version: str | None) -> bool:
    return protocol_version in _TLS12_AND_EARLIER


@rule(
    rule_id="external.tls_secure_renegotiation_not_observed",
    title="TLS secure renegotiation not observed",
    severity="medium",
    description=(
        "The initial TLS handshake did not advertise RFC 5746 secure "
        "renegotiation support."
    ),
    recommendation=(
        "Enable RFC 5746 secure renegotiation support for TLS 1.2 and earlier, "
        "or prefer TLS 1.3-only deployments."
    ),
    category="external",
    input_kind="probe",
    standards=(
        nist_sp(
            "800-52 Rev. 2",
            "3.5",
            coverage="partial",
            note="Initial handshake advertisement only.",
        ),
        cwe(327),
    ),
    order=716,
)
def find_tls_secure_renegotiation_not_observed(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        tls_info = attempt.tls_info
        if tls_info is None or not _tls12_or_earlier(tls_info.protocol_version):
            continue
        if tls_info.renegotiation_info_observed is not False:
            continue

        protocol_version = tls_info.protocol_version or "unknown"
        findings.append(
            Finding(
                rule_id="external.tls_secure_renegotiation_not_observed",
                title="TLS secure renegotiation not observed",
                severity="medium",
                description=(
                    f"The observed {protocol_version} ServerHello did not include "
                    "the RFC 5746 renegotiation_info extension. TLS 1.2 and "
                    "earlier endpoints that omit this signal can be vulnerable "
                    "to insecure renegotiation downgrade scenarios."
                ),
                recommendation=(
                    "Enable RFC 5746 secure renegotiation support for TLS 1.2 "
                    "and earlier, or disable those protocol versions entirely."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=(
                        f"protocol: {protocol_version}, "
                        "renegotiation_info_observed: False"
                    ),
                ),
            )
        )

    return findings


@rule(
    rule_id="external.tls_negotiated_compression",
    title="TLS compression negotiated",
    severity="medium",
    description="The negotiated TLS session used TLS-level compression.",
    recommendation=(
        "Disable TLS-level compression for TLS 1.2 and earlier to avoid "
        "CRIME-class attacks."
    ),
    category="external",
    input_kind="probe",
    standards=(
        nist_sp(
            "800-52 Rev. 2",
            "3.6",
            coverage="partial",
            note="Initial handshake observation only.",
        ),
        cwe(310),
        owasp_top10_2021("A02:2021"),
    ),
    order=717,
)
def find_tls_negotiated_compression(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        tls_info = attempt.tls_info
        if tls_info is None or not _tls12_or_earlier(tls_info.protocol_version):
            continue

        compression = tls_info.negotiated_compression
        if compression is None or compression == "null":
            continue

        protocol_version = tls_info.protocol_version or "unknown"
        findings.append(
            Finding(
                rule_id="external.tls_negotiated_compression",
                title="TLS compression negotiated",
                severity="medium",
                description=(
                    f"The observed {protocol_version} handshake negotiated "
                    f"TLS-level compression ({compression}). Compression can "
                    "re-enable CRIME-class plaintext disclosure attacks."
                ),
                recommendation=(
                    "Disable TLS-level compression for TLS 1.2 and earlier."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=(
                        f"protocol: {protocol_version}, compression: {compression}"
                    ),
                ),
            )
        )

    return findings


@rule(
    rule_id="external.tls_aead_cipher_not_negotiated",
    title="Non-AEAD TLS cipher negotiated",
    severity="low",
    description=(
        "The negotiated TLS cipher does not use an AEAD construction."
    ),
    recommendation=(
        "Prefer TLS 1.3 or AEAD TLS 1.2 cipher suites such as AES-GCM or "
        "ChaCha20-Poly1305."
    ),
    category="external",
    input_kind="probe",
    standards=(
        nist_sp(
            "800-52 Rev. 2",
            "3.3.1",
            coverage="partial",
            note="Observed negotiated cipher posture only.",
        ),
        asvs_5("12.1.2"),
        cwe(327),
    ),
    order=718,
)
def find_tls_aead_cipher_not_negotiated(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        tls_info = attempt.tls_info
        if tls_info is None or not _tls12_or_earlier(tls_info.protocol_version):
            continue
        if tls_info.cipher_name is None:
            continue
        if tls_info.negotiated_cipher_is_aead is not False:
            continue

        protocol_version = tls_info.protocol_version or "unknown"
        findings.append(
            Finding(
                rule_id="external.tls_aead_cipher_not_negotiated",
                title="Non-AEAD TLS cipher negotiated",
                severity="low",
                description=(
                    f"The observed {protocol_version} handshake negotiated the "
                    f"non-AEAD cipher '{tls_info.cipher_name}'. CBC-plus-HMAC "
                    "cipher suites are weaker modern posture than AEAD suites."
                ),
                recommendation=(
                    "Prefer TLS 1.3 or AEAD TLS 1.2 cipher suites such as "
                    "AES-GCM or ChaCha20-Poly1305."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=(
                        f"protocol: {protocol_version}, cipher: {tls_info.cipher_name}, "
                        "negotiated_cipher_is_aead: False"
                    ),
                ),
            )
        )

    return findings


__all__ = [
    "find_tls_aead_cipher_not_negotiated",
    "find_tls_negotiated_compression",
    "find_tls_secure_renegotiation_not_observed",
]
