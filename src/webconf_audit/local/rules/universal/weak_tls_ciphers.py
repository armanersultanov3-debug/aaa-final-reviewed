"""universal.weak_tls_ciphers

Fires when the cipher string contains weak or legacy TLS cipher posture.
Skips silently when ciphers are unknown (None).
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021
from webconf_audit.tls_cipher_policy import (
    analyze_cipher_policy,
    describe_cipher_policy_issues,
)

RULE_ID = "universal.weak_tls_ciphers"
TITLE = "Insufficient TLS cipher posture"


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=(
        "The cipher string contains weak components or lacks explicit modern "
        "cipher posture."
    ),
    recommendation=(
        "Remove weak ciphers and use explicit forward-secret AEAD cipher suites."
    ),
    category="universal",
    input_kind="normalized",
    tags=("tls",),
    standards=(
        cwe(327),
        owasp_top10_2021("A02:2021"),
        asvs_5(
            "12.1.2",
            coverage="partial",
            note="Conservative cipher-string posture checks.",
        ),
    ),
    order=102,
)
def check(config: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []
    for scope in config.scopes:
        if scope.tls is None or scope.tls.ciphers is None:
            continue
        assessment = analyze_cipher_policy(scope.tls.ciphers)
        if not assessment.has_issue:
            continue
        issues = describe_cipher_policy_issues(assessment)
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="medium",
                description=(
                    f"Scope '{scope.scope_name or '(unnamed)'}' cipher string "
                    f"has weak posture: {'; '.join(issues)}."
                ),
                recommendation=(
                    "Remove weak ciphers and use explicit forward-secret AEAD "
                    "cipher suites."
                ),
                location=_location(scope, config),
            )
        )
    return findings


def _location(scope, config: NormalizedConfig) -> SourceLocation:
    src = scope.tls.source
    details = f"server_type={config.server_type}"
    if src.details:
        details = f"{details}; {src.details}"
    return SourceLocation(
        mode="local",
        kind="xml" if src.xml_path else "file",
        file_path=src.file_path,
        line=src.line,
        xml_path=src.xml_path,
        details=details,
    )
