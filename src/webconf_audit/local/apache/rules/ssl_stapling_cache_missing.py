from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._tls_policy_utils import (
    directive_args,
    first_arg_lower,
    iter_tls_scopes,
    make_tls_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ssl_stapling_cache_missing"
TITLE = "Apache OCSP stapling cache is missing"


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description="An Apache TLS scope enables OCSP stapling without SSLStaplingCache.",
    recommendation="Configure SSLStaplingCache when SSLUseStapling is enabled.",
    category="local",
    server_type="apache",
    order=355,
    tags=("tls",),
)
def find_ssl_stapling_cache_missing(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        if first_arg_lower(scope.directives.get("sslusestapling")) != "on":
            continue
        directive = scope.directives.get("sslstaplingcache")
        if directive is not None and directive_args(directive):
            continue
        findings.append(
            make_tls_finding(
                scope,
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    f"TLS scope '{scope.label}' enables SSLUseStapling but does "
                    "not configure SSLStaplingCache."
                ),
                recommendation="Set SSLStaplingCache to a shared cache provider.",
                directive=directive,
            )
        )
    return findings


__all__ = ["find_ssl_stapling_cache_missing"]
