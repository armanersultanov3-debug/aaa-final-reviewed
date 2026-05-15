"""Implements rule ``apache.referrer_policy_unsafe``.

Location: ``src/webconf_audit/local/apache/rules/referrer_policy_unsafe.py``.
"""

from __future__ import annotations

from webconf_audit.header_policy import referrer_policy_is_safe
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import (
    unsafe_header_findings,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.referrer_policy_unsafe"
TITLE = "Referrer-Policy header is weak"
DESCRIPTION = "Apache sets Referrer-Policy to a weak value."
RECOMMENDATION = (
    "Use 'Header set Referrer-Policy strict-origin-when-cross-origin' "
    "or 'Header set Referrer-Policy no-referrer'."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    tags=("headers",),
    order=337,
)
def find_referrer_policy_unsafe(config_ast: ApacheConfigAst) -> list[Finding]:
    return unsafe_header_findings(
        config_ast,
        header_name="Referrer-Policy",
        is_safe_value=referrer_policy_is_safe,
        rule_id=RULE_ID,
        title=TITLE,
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
    )


__all__ = ["find_referrer_policy_unsafe"]
