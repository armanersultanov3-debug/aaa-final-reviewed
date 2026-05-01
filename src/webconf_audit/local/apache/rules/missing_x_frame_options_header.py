from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import (
    missing_header_findings,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_x_frame_options_header"


@rule(
    rule_id=RULE_ID,
    title="Missing X-Frame-Options header",
    severity="low",
    description="Apache server scope does not define an X-Frame-Options header.",
    recommendation=(
        "Add 'Header set X-Frame-Options SAMEORIGIN' or "
        "'Header set X-Frame-Options DENY'."
    ),
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
        title="Missing X-Frame-Options header",
        description="Apache server scope does not define an X-Frame-Options header.",
        recommendation=(
            "Add 'Header set X-Frame-Options SAMEORIGIN' or "
            "'Header set X-Frame-Options DENY'."
        ),
    )


__all__ = ["find_missing_x_frame_options_header"]
