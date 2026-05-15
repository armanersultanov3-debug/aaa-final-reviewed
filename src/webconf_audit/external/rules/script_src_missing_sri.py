"""Implements rule ``external.script_src_missing_sri``.

Location: ``src/webconf_audit/external/rules/script_src_missing_sri.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021, pci_dss_4

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt


@rule(
    rule_id="external.script_src_missing_sri",
    title="Cross-origin script source missing SRI",
    severity="medium",
    description=(
        "A cross-origin <script src=...> was observed without an integrity "
        "attribute."
    ),
    recommendation=(
        "Add a Subresource Integrity hash to every cross-origin script tag "
        "and ensure the referenced resource is served with compatible CORS "
        "headers."
    ),
    category="external",
    input_kind="probe",
    standards=(
        cwe(353),
        owasp_top10_2021("A08:2021"),
        pci_dss_4("6.4.3"),
        asvs_5("3.4.3", coverage="partial", note="SRI on cross-origin scripts only."),
    ),
    order=658,
)
def find_script_src_missing_sri(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in probe_attempts:
        if attempt.target.scheme != "https":
            continue
        if not attempt.has_http_response or attempt.status_code != 200:
            continue
        if attempt.html_recon is None:
            continue

        for script in attempt.html_recon.external_scripts:
            if not _script_src_is_cross_origin(script.src, attempt):
                continue
            if script.integrity is not None:
                continue
            findings.append(
                Finding(
                    rule_id="external.script_src_missing_sri",
                    title="Cross-origin script source missing SRI",
                    severity="medium",
                    description=(
                        "The HTML response includes a cross-origin script source "
                        f"({script.src}) without an integrity attribute. This "
                        "weakens browser-side protection against compromised or "
                        "tampered third-party script delivery."
                    ),
                    recommendation=(
                        "Add an integrity attribute for the script and keep the "
                        "hash updated when the dependency changes."
                    ),
                    location=SourceLocation(
                        mode="external",
                        kind="url",
                        target=attempt.target.url,
                        details=f"script src: {script.src}",
                    ),
                    metadata={
                        "script_src": script.src,
                        "crossorigin": script.crossorigin,
                        "nonce": script.nonce,
                    },
                )
            )

    return findings


def _script_src_is_cross_origin(src: str, attempt: "ProbeAttempt") -> bool:
    normalized_src = src.strip()
    if not normalized_src:
        return False

    parsed_src = urlsplit(normalized_src)
    if not parsed_src.scheme and not parsed_src.netloc:
        return False

    resolved = urlsplit(urljoin(attempt.target.url, normalized_src))
    if resolved.scheme not in {"http", "https"}:
        return False

    resolved_host = (resolved.hostname or "").lower()
    target_host = attempt.target.host.lower()
    resolved_port = resolved.port or (443 if resolved.scheme == "https" else 80)

    return (
        resolved.scheme != attempt.target.scheme
        or resolved_host != target_host
        or resolved_port != attempt.target.port
    )


__all__ = ["find_script_src_missing_sri"]
