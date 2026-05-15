"""Implements rule ``external.iis.server_header_removal_not_applied``.

Location: ``src/webconf_audit/external/rules/iis_native_header_probe.py``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from webconf_audit.external.rules._helpers import _is_iis_conditional_applicable
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cis_iis_10_v1_2_1, cwe, nist_sp

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt, ServerIdentification

_IIS_SERVER_HEADER_PATTERN = re.compile(r"(?i)\bmicrosoft-iis(?:/|\b)")


@rule(
    rule_id="external.iis.server_header_removal_not_applied",
    title="IIS Server header removal not applied at runtime",
    severity="low",
    description=(
        "An IIS-identified endpoint still emits the native Microsoft-IIS "
        "Server header at runtime."
    ),
    recommendation=(
        "Verify that IIS native Server header suppression is effective at "
        "runtime and that no intermediary restores the Microsoft-IIS header."
    ),
    category="external",
    input_kind="probe",
    condition="iis",
    standards=(
        cis_iis_10_v1_2_1(
            "3.11",
            coverage="partial",
            note="Runtime evidence of Server header presence.",
        ),
        cwe(200),
        nist_sp("800-53 Rev. 5", "SI-11"),
    ),
    order=617,
)
def find_iis_server_header_removal_not_applied(
    probe_attempts: list["ProbeAttempt"],
    server_identification: "ServerIdentification | None" = None,
) -> list[Finding]:
    if not _is_iis_conditional_applicable(server_identification):
        return []

    findings: list[Finding] = []
    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if not _is_native_iis_server_header(attempt.server_header):
            continue

        findings.append(
            Finding(
                rule_id="external.iis.server_header_removal_not_applied",
                title="IIS Server header removal not applied at runtime",
                severity="low",
                description=(
                    "The response still exposes the native Microsoft-IIS "
                    "Server header on an endpoint fingerprinted as IIS, which "
                    "shows that runtime header suppression is not taking effect."
                ),
                recommendation=(
                    "Confirm that requestFiltering removeServerHeader is "
                    "effective for the deployed path and that upstream "
                    "components are not reintroducing the Microsoft-IIS "
                    "Server header."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Server: {attempt.server_header}",
                ),
                metadata={
                    "observation_source": "runtime_server_header",
                    "observed_header_name": "Server",
                    "observed_header_value": attempt.server_header,
                    "complementary_rule_id": (
                        "iis.request_filtering_remove_server_header_disabled"
                    ),
                },
            )
        )

    return findings


def _is_native_iis_server_header(server_header: str | None) -> bool:
    return (
        server_header is not None
        and _IIS_SERVER_HEADER_PATTERN.search(server_header) is not None
    )


__all__ = ["find_iis_server_header_removal_not_applied"]
