from __future__ import annotations

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
_SAFE_REFERRER_POLICIES = frozenset({"no-referrer", "strict-origin-when-cross-origin"})
_KNOWN_REFERRER_POLICIES = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
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
        is_safe_value=_is_safe_referrer_policy,
        rule_id=RULE_ID,
        title=TITLE,
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
    )


def _is_safe_referrer_policy(value: str | None) -> bool:
    if value is None:
        return False
    cleaned = value.strip().strip('"').strip("'").lower()
    if not cleaned:
        return False
    tokens = [token.strip() for token in cleaned.split(",") if token.strip()]
    for token in reversed(tokens):
        if token in _KNOWN_REFERRER_POLICIES:
            return token in _SAFE_REFERRER_POLICIES
    return False


__all__ = ["find_referrer_policy_unsafe"]
