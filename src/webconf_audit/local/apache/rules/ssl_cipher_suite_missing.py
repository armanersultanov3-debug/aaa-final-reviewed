from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._tls_policy_utils import (
    directive_args,
    iter_tls_scopes,
    make_tls_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ssl_cipher_suite_missing"
TITLE = "Apache TLS cipher suite policy is missing"


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description="A TLS-enabled Apache scope does not define SSLCipherSuite.",
    recommendation="Configure SSLCipherSuite with an explicit approved cipher policy.",
    category="local",
    server_type="apache",
    order=350,
    tags=("tls",),
)
def find_ssl_cipher_suite_missing(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        directive = scope.directives.get("sslciphersuite")
        if directive is not None and directive_args(directive):
            continue
        findings.append(
            make_tls_finding(
                scope,
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    f"TLS scope '{scope.label}' does not define an effective "
                    "SSLCipherSuite policy."
                ),
                recommendation="Set SSLCipherSuite to an explicit approved cipher list.",
                directive=directive,
            )
        )
    return findings


__all__ = ["find_ssl_cipher_suite_missing"]
