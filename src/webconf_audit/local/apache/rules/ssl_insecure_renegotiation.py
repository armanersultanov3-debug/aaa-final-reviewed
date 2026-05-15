"""Implements rule ``apache.ssl_insecure_renegotiation_enabled``.

Location: ``src/webconf_audit/local/apache/rules/ssl_insecure_renegotiation.py``.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._tls_policy_utils import (
    first_arg_lower,
    iter_tls_scopes,
    make_tls_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ssl_insecure_renegotiation_enabled"
TITLE = "Apache insecure TLS renegotiation is enabled"


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="high",
    description=(
        "A TLS-enabled Apache scope explicitly enables SSLInsecureRenegotiation."
    ),
    recommendation="Set SSLInsecureRenegotiation Off or remove the directive.",
    category="local",
    server_type="apache",
    order=353,
    tags=("tls",),
)
def find_ssl_insecure_renegotiation_enabled(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        directive = scope.directives.get("sslinsecurerenegotiation")
        if first_arg_lower(directive) != "on":
            continue
        findings.append(
            make_tls_finding(
                scope,
                rule_id=RULE_ID,
                title=TITLE,
                severity="high",
                description=(
                    f"TLS scope '{scope.label}' sets "
                    "SSLInsecureRenegotiation On."
                ),
                recommendation="Disable insecure TLS renegotiation.",
                directive=directive,
            )
        )
    return findings


__all__ = ["find_ssl_insecure_renegotiation_enabled"]
