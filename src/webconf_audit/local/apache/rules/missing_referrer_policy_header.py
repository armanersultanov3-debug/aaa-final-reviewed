from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import (
    missing_header_findings,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_referrer_policy_header"
TITLE = "Missing Referrer-Policy header"
DESCRIPTION = "Apache server scope does not define a Referrer-Policy header."
RECOMMENDATION = (
    "Add 'Header set Referrer-Policy strict-origin-when-cross-origin' "
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
    order=336,
)
def find_missing_referrer_policy_header(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    return missing_header_findings(
        config_ast,
        header_name="Referrer-Policy",
        rule_id=RULE_ID,
        title=TITLE,
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
    )


__all__ = ["find_missing_referrer_policy_header"]
