from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._tls_policy_utils import (
    first_arg_lower,
    iter_tls_scopes,
    make_tls_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ssl_session_cache_missing"
TITLE = "Apache TLS session cache is missing or disabled"


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description="A TLS-enabled Apache scope does not configure a usable SSLSessionCache.",
    recommendation="Configure SSLSessionCache with a shared cache provider.",
    category="local",
    server_type="apache",
    order=356,
    tags=("tls",),
)
def find_ssl_session_cache_missing(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        directive = scope.directives.get("sslsessioncache")
        value = first_arg_lower(directive)
        if value is not None and value not in {"none", "nonenotnull"}:
            continue
        findings.append(
            make_tls_finding(
                scope,
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    f"TLS scope '{scope.label}' does not configure a usable "
                    "SSLSessionCache."
                ),
                recommendation="Set SSLSessionCache to a shared cache provider.",
                directive=directive,
            )
        )
    return findings


__all__ = ["find_ssl_session_cache_missing"]
