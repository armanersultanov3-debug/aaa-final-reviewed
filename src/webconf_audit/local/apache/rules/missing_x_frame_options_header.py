from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import (
    missing_header_findings,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_x_frame_options_header"
TITLE = "Missing X-Frame-Options header"
DESCRIPTION = "Apache server scope does not define an X-Frame-Options header."
RECOMMENDATION = (
    "Add 'Header set X-Frame-Options SAMEORIGIN' or "
    "'Header set X-Frame-Options DENY'."
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
    order=334,
)
def find_missing_x_frame_options_header(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    return missing_header_findings(
        config_ast,
        header_name="X-Frame-Options",
        rule_id=RULE_ID,
        title=TITLE,
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
    )


__all__ = ["find_missing_x_frame_options_header"]
