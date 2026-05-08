from __future__ import annotations

from webconf_audit.header_policy import content_security_policy_has_frame_ancestors
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import unsafe_header_findings
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "apache.content_security_policy_missing_frame_ancestors"


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy missing frame-ancestors",
    severity="low",
    description="Content-Security-Policy is configured without frame-ancestors.",
    recommendation=(
        "Add a restrictive frame-ancestors directive such as 'none' or "
        "'self' to Content-Security-Policy."
    ),
    category="local",
    server_type="apache",
    tags=("headers",),
    standards=(
        cwe(1021),
        owasp_top10_2021("A05:2021"),
        asvs_5("3.4.6"),
    ),
    order=364,
)
def find_content_security_policy_missing_frame_ancestors(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    return unsafe_header_findings(
        config_ast,
        header_name="Content-Security-Policy",
        is_safe_value=content_security_policy_has_frame_ancestors,
        rule_id=RULE_ID,
        title="Content-Security-Policy missing frame-ancestors",
        description=(
            "Content-Security-Policy is configured without a frame-ancestors "
            "directive, so clickjacking restrictions still depend on legacy "
            "X-Frame-Options behavior."
        ),
        recommendation=(
            "Add a restrictive frame-ancestors directive such as 'none' or "
            "'self' to Content-Security-Policy."
        ),
    )


__all__ = ["find_content_security_policy_missing_frame_ancestors"]
