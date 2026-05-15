"""Implements rule ``apache.permissions_policy_unsafe``.

Location: ``src/webconf_audit/local/apache/rules/permissions_policy_unsafe.py``.
"""

from __future__ import annotations

from webconf_audit.header_policy import permissions_policy_is_safe
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import (
    unsafe_header_findings,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.permissions_policy_unsafe"
TITLE = "Permissions-Policy header is overly broad"
DESCRIPTION = "Apache sets Permissions-Policy to an overly broad value."
RECOMMENDATION = (
    "Use a least-privilege Permissions-Policy allowlist and avoid wildcard "
    "feature grants."
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
    order=339,
)
def find_permissions_policy_unsafe(config_ast: ApacheConfigAst) -> list[Finding]:
    return unsafe_header_findings(
        config_ast,
        header_name="Permissions-Policy",
        is_safe_value=permissions_policy_is_safe,
        rule_id=RULE_ID,
        title=TITLE,
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
    )


__all__ = ["find_permissions_policy_unsafe"]
