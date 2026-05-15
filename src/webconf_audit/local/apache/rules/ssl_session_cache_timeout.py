"""Implements rule ``apache.ssl_session_cache_timeout_missing_or_invalid``.

Location: ``src/webconf_audit/local/apache/rules/ssl_session_cache_timeout.py``.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._tls_policy_utils import (
    directive_args,
    iter_tls_scopes,
    make_tls_finding,
)
from webconf_audit.local.apache.rules.server_directive_utils import (
    parse_single_positive_int,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ssl_session_cache_timeout_missing_or_invalid"
TITLE = "Apache TLS session cache timeout is missing or invalid"
MAX_TIMEOUT_SECONDS = 300


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=(
        "A TLS-enabled Apache scope does not configure SSLSessionCacheTimeout "
        "to 300 seconds or less."
    ),
    recommendation="Set SSLSessionCacheTimeout to a positive value of 300 seconds or less.",
    category="local",
    server_type="apache",
    order=365,
    tags=("tls",),
)
def find_ssl_session_cache_timeout_missing_or_invalid(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        directive = scope.directives.get("sslsessioncachetimeout")
        value = parse_single_positive_int(directive_args(directive))
        if value is not None and value <= MAX_TIMEOUT_SECONDS:
            continue
        findings.append(
            make_tls_finding(
                scope,
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    f"TLS scope '{scope.label}' does not configure "
                    "SSLSessionCacheTimeout to 300 seconds or less."
                ),
                recommendation=(
                    "Set SSLSessionCacheTimeout to a positive value of "
                    "300 seconds or less."
                ),
                directive=directive,
            )
        )
    return findings


__all__ = ["find_ssl_session_cache_timeout_missing_or_invalid"]
