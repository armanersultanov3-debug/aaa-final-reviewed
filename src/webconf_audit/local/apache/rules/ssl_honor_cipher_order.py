from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._tls_policy_utils import (
    first_arg_lower,
    iter_tls_scopes,
    make_tls_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ssl_honor_cipher_order_not_on"
TITLE = "Apache TLS cipher order does not prefer the server"


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description="A TLS-enabled Apache scope does not set SSLHonorCipherOrder On.",
    recommendation="Set SSLHonorCipherOrder On so the server controls cipher preference.",
    category="local",
    server_type="apache",
    order=351,
    tags=("tls",),
)
def find_ssl_honor_cipher_order(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        directive = scope.directives.get("sslhonorcipherorder")
        if first_arg_lower(directive) == "on":
            continue
        findings.append(
            make_tls_finding(
                scope,
                rule_id=RULE_ID,
                title=TITLE,
                severity="medium",
                description=(
                    f"TLS scope '{scope.label}' does not set "
                    "SSLHonorCipherOrder On."
                ),
                recommendation="Set SSLHonorCipherOrder On for TLS scopes.",
                directive=directive,
            )
        )
    return findings


__all__ = ["find_ssl_honor_cipher_order"]
