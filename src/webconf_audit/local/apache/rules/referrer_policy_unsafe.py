from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import (
    unsafe_header_findings,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.referrer_policy_unsafe"
_SAFE_REFERRER_POLICIES = frozenset({"no-referrer", "strict-origin-when-cross-origin"})


@rule(
    rule_id=RULE_ID,
    title="Referrer-Policy header is weak",
    severity="low",
    description="Apache sets Referrer-Policy to a weak value.",
    recommendation=(
        "Use 'Header set Referrer-Policy strict-origin-when-cross-origin' "
        "or 'Header set Referrer-Policy no-referrer'."
    ),
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
        title="Referrer-Policy header is weak",
        description="Apache sets Referrer-Policy to a weak value.",
        recommendation=(
            "Use 'Header set Referrer-Policy strict-origin-when-cross-origin' "
            "or 'Header set Referrer-Policy no-referrer'."
        ),
    )


def _is_safe_referrer_policy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().strip('"').strip("'").lower() in _SAFE_REFERRER_POLICIES


__all__ = ["find_referrer_policy_unsafe"]
