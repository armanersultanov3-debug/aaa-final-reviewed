"""Implements rule ``apache.missing_permissions_policy_header``.

Location: ``src/webconf_audit/local/apache/rules/missing_permissions_policy_header.py``.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import (
    missing_header_findings,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_permissions_policy_header"
TITLE = "Missing Permissions-Policy header"
DESCRIPTION = "Apache server scope does not define a Permissions-Policy header."
RECOMMENDATION = "Add a least-privilege Permissions-Policy header."


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    tags=("headers",),
    order=338,
)
def find_missing_permissions_policy_header(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    return missing_header_findings(
        config_ast,
        header_name="Permissions-Policy",
        rule_id=RULE_ID,
        title=TITLE,
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
    )


__all__ = ["find_missing_permissions_policy_header"]
