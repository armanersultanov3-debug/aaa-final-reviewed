"""universal.tls_required_for_authenticated_routes

Fires when an authentication-requiring scope is exposed on a non-TLS listener.
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, nist_sp, owasp_top10_2021, pci_dss_4

RULE_ID = "universal.tls_required_for_authenticated_routes"
TITLE = "Authentication-requiring scope exposed on non-TLS listener"
DESCRIPTION = "Authentication-requiring scope is exposed on a non-TLS listener."
RECOMMENDATION = (
    "Serve authentication-requiring scopes only over TLS, or redirect plain HTTP "
    "before credentials are requested."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="high",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="universal",
    input_kind="normalized",
    tags=("auth", "tls"),
    standards=(
        nist_sp("800-53 Rev. 5", "SC-8"),
        pci_dss_4("8.3.2"),
        cwe(319),
        owasp_top10_2021("A02:2021"),
        asvs_5("3.7.1"),
    ),
    order=109,
)
def check(config: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []
    for auth_loc in config.auth_requiring_locations:
        if auth_loc.requires_tls:
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="high",
                description=(
                    f"Authentication-requiring scope [{auth_loc.path}] is exposed "
                    "on a non-TLS listener."
                ),
                recommendation=RECOMMENDATION,
                location=_finding_location(auth_loc.source, config.server_type),
                metadata={
                    "path": auth_loc.path,
                    "auth_kind": auth_loc.auth_kind,
                    "requires_tls": auth_loc.requires_tls,
                },
            )
        )
    return findings


def _finding_location(source: SourceLocation, server_type: str) -> SourceLocation:
    return SourceLocation(
        mode=source.mode,
        kind=source.kind,
        file_path=source.file_path,
        line=source.line,
        xml_path=source.xml_path,
        target=source.target,
        details=f"server_type={server_type}",
    )
