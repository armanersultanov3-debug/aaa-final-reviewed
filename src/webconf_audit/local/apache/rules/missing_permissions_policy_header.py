from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import (
    missing_header_findings,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_permissions_policy_header"


@rule(
    rule_id=RULE_ID,
    title="Missing Permissions-Policy header",
    severity="low",
    description="Apache server scope does not define a Permissions-Policy header.",
    recommendation="Add a least-privilege Permissions-Policy header.",
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
        title="Missing Permissions-Policy header",
        description="Apache server scope does not define a Permissions-Policy header.",
        recommendation="Add a least-privilege Permissions-Policy header.",
    )


__all__ = ["find_missing_permissions_policy_header"]
