"""Apache CVE-related SSLEngine optional rule."""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.server_directive_utils import (
    deduplicate_findings_by_location,
    directive_location,
    iter_effective_server_directives,
    virtualhost_label,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import StandardReference, rule

RULE_ID = "apache.ssl_engine_optional"
TITLE = "Apache SSLEngine is set to optional"
DESCRIPTION = (
    "Apache sets SSLEngine optional. This CVE-2025-49812-related TLS mode is "
    "deployment- and version-dependent, but optional TLS can make transport "
    "security expectations ambiguous and should be reviewed."
)
RECOMMENDATION = (
    "Use explicit SSLEngine On or Off for the scope, avoid optional TLS unless "
    "there is a documented requirement, and confirm the Apache HTTP Server "
    "version is patched for CVE-2025-49812."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    tags=("cve", "tls"),
    standards=(
        StandardReference(
            standard="CVE",
            reference="CVE-2025-49812",
            url="https://httpd.apache.org/security/vulnerabilities_24.html",
            coverage="related",
            note=(
                "Detects SSLEngine optional; affected-version state and actual "
                "client-negotiation behaviour are not proven."
            ),
        ),
    ),
    order=367,
)
def find_ssl_engine_optional(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for context, directive in iter_effective_server_directives(config_ast, "sslengine"):
        if directive is None or not directive.args:
            continue
        first = directive.args[0]
        if isinstance(first, list) or first.lower() != "optional":
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="medium",
                description=f"{DESCRIPTION} Scope: {virtualhost_label(context)}.",
                recommendation=RECOMMENDATION,
                location=directive_location(directive),
            )
        )
    return deduplicate_findings_by_location(findings)


__all__ = ["find_ssl_engine_optional"]
