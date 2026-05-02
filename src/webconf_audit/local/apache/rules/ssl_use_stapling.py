from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._tls_policy_utils import (
    first_arg_lower,
    iter_tls_scopes,
    make_tls_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ssl_use_stapling_not_on"
TITLE = "Apache OCSP stapling is not enabled"


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description="A TLS-enabled Apache scope does not set SSLUseStapling On.",
    recommendation="Set SSLUseStapling On for TLS scopes and configure a stapling cache.",
    category="local",
    server_type="apache",
    order=354,
    tags=("tls",),
)
def find_ssl_use_stapling(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        directive = scope.directives.get("sslusestapling")
        if first_arg_lower(directive) == "on":
            continue
        findings.append(
            make_tls_finding(
                scope,
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    f"TLS scope '{scope.label}' does not set SSLUseStapling On."
                ),
                recommendation="Set SSLUseStapling On and configure SSLStaplingCache.",
                directive=directive,
            )
        )
    return findings


__all__ = ["find_ssl_use_stapling"]
