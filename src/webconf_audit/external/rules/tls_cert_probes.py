"""Implements rules: ``external.tls_ct_log_evidence_missing``, ``external.tls_weak_signature_algorithm``, ``external.tls_must_staple_not_observed``.

Location: ``src/webconf_audit/external/rules/tls_cert_probes.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.recon.tls_probe import (
    describe_signature_algorithm,
    signature_algorithm_is_weak,
)
from webconf_audit.external.rules._helpers import _successful_attempts_for_scheme
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, nist_sp, owasp_top10_2021

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt, TLSInfo


@rule(
    rule_id="external.tls_ct_log_evidence_missing",
    title="TLS certificate transparency evidence not observed",
    severity="low",
    description="No embedded or stapled SCT evidence was observed for the TLS certificate.",
    recommendation="Use a publicly trusted certificate that carries CT log evidence via embedded or stapled SCTs.",
    category="external",
    input_kind="probe",
    standards=(
        nist_sp("800-52 Rev. 2", "3.4"),
        cwe(295),
        asvs_5("12.2.2"),
    ),
    order=713,
)
def find_tls_ct_log_evidence_missing(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        tls_info = attempt.tls_info
        if tls_info is None or _leaf_certificate_is_self_signed(tls_info):
            continue
        if tls_info.embedded_scts or tls_info.stapled_scts:
            continue

        findings.append(
            Finding(
                rule_id="external.tls_ct_log_evidence_missing",
                title="TLS certificate transparency evidence not observed",
                severity="low",
                description=(
                    "The observed certificate did not include embedded Signed "
                    "Certificate Timestamps (SCTs), and the handshake did not "
                    "return any stapled SCTs. Publicly trusted Web PKI "
                    "certificates are expected to present CT log evidence."
                ),
                recommendation=(
                    "Issue the certificate through a CA workflow that embeds "
                    "or staples certificate transparency SCT evidence."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details="embedded_scts: 0, stapled_scts: 0",
                ),
            )
        )

    return findings


@rule(
    rule_id="external.tls_weak_signature_algorithm",
    title="Weak certificate signature algorithm observed",
    severity="medium",
    description="A certificate in the served chain uses a weak MD5 or SHA-1 signature algorithm.",
    recommendation="Replace certificates that still rely on MD5 or SHA-1 signatures with SHA-256-or-stronger signatures.",
    category="external",
    input_kind="probe",
    standards=(
        nist_sp("800-52 Rev. 2", "3.4"),
        cwe(327),
        owasp_top10_2021("A02:2021"),
    ),
    order=714,
)
def find_tls_weak_signature_algorithm(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        tls_info = attempt.tls_info
        if tls_info is None or _leaf_certificate_is_self_signed(tls_info):
            continue

        for position, certificate in enumerate(tls_info.chain_certificates, start=1):
            if certificate.self_signed:
                continue
            if not signature_algorithm_is_weak(
                certificate.signature_oid,
                certificate.signature_name,
            ):
                continue

            certificate_label = certificate.subject or f"certificate #{position}"
            signature_label = describe_signature_algorithm(
                certificate.signature_oid,
                certificate.signature_name,
            )

            findings.append(
                Finding(
                    rule_id="external.tls_weak_signature_algorithm",
                    title="Weak certificate signature algorithm observed",
                    severity="medium",
                    description=(
                        f"{certificate_label} in the served certificate chain uses "
                        f"the weak signature algorithm {signature_label}. MD5 and "
                        "SHA-1 signatures are deprecated and collision-prone."
                    ),
                    recommendation=(
                        "Replace the affected certificate with one signed using "
                        "SHA-256 or a stronger modern signature algorithm."
                    ),
                    location=SourceLocation(
                        mode="external",
                        kind="tls",
                        target=attempt.target.url,
                        details=(
                            f"certificate: {certificate_label}, "
                            f"signature: {signature_label}"
                        ),
                    ),
                )
            )

    return findings


@rule(
    rule_id="external.tls_must_staple_not_observed",
    title="Must-staple certificate observed without OCSP staple",
    severity="medium",
    description="The certificate advertises must-staple, but no OCSP staple was observed in the TLS handshake.",
    recommendation="Serve a valid OCSP staple whenever the certificate includes the TLS Feature must-staple flag.",
    category="external",
    input_kind="probe",
    standards=(
        nist_sp("800-52 Rev. 2", "4.2"),
        asvs_5("12.1.4"),
        cwe(295),
    ),
    order=715,
)
def find_tls_must_staple_not_observed(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        tls_info = attempt.tls_info
        if tls_info is None:
            continue
        if not tls_info.cert_must_staple:
            continue
        if tls_info.ocsp_stapled is not False:
            continue

        findings.append(
            Finding(
                rule_id="external.tls_must_staple_not_observed",
                title="Must-staple certificate observed without OCSP staple",
                severity="medium",
                description=(
                    "The served certificate includes the TLS Feature "
                    "must-staple flag, but the observed TLS handshake did not "
                    "contain an OCSP staple. Clients that enforce must-staple "
                    "may reject the connection."
                ),
                recommendation=(
                    "Enable OCSP stapling and ensure the server can fetch and "
                    "refresh the certificate's OCSP response."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details="cert_must_staple: True, ocsp_stapled: False",
                ),
            )
        )

    return findings


def _leaf_certificate_is_self_signed(tls_info: "TLSInfo") -> bool:
    if tls_info.chain_certificates:
        return tls_info.chain_certificates[0].self_signed
    return (
        tls_info.cert_subject is not None
        and tls_info.cert_issuer is not None
        and tls_info.cert_subject == tls_info.cert_issuer
    )


__all__ = [
    "find_tls_ct_log_evidence_missing",
    "find_tls_must_staple_not_observed",
    "find_tls_weak_signature_algorithm",
]
