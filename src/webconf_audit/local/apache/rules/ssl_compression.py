"""Implements rule ``apache.ssl_compression_enabled``.

Location: ``src/webconf_audit/local/apache/rules/ssl_compression.py``.
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

RULE_ID = "apache.ssl_compression_enabled"
TITLE = "Apache TLS compression is enabled"


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description="A TLS-enabled Apache scope explicitly enables SSLCompression.",
    recommendation="Set SSLCompression Off or omit it on Apache builds where Off is the default.",
    category="local",
    server_type="apache",
    order=352,
    tags=("tls",),
)
def find_ssl_compression_enabled(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        directive = scope.directives.get("sslcompression")
        if first_arg_lower(directive) != "on":
            continue
        findings.append(
            make_tls_finding(
                scope,
                rule_id=RULE_ID,
                title=TITLE,
                severity="medium",
                description=(
                    f"TLS scope '{scope.label}' sets SSLCompression On, "
                    "which can expose compressed TLS traffic to CRIME-style attacks."
                ),
                recommendation="Set SSLCompression Off.",
                directive=directive,
            )
        )
    return findings


__all__ = ["find_ssl_compression_enabled"]
