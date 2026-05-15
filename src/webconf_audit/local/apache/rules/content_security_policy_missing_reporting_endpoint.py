"""apache.content_security_policy_missing_reporting_endpoint -- Content-Security-Policy missing reporting endpoint."""

from __future__ import annotations

from webconf_audit.csp import content_security_policy_has_reporting_endpoint
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import unsafe_header_findings
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "apache.content_security_policy_missing_reporting_endpoint"


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy missing reporting endpoint",
    severity="low",
    description="Content-Security-Policy is configured without report-uri or report-to.",
    recommendation=(
        "Add a CSP report-to or report-uri directive pointing at a controlled "
        "reporting endpoint."
    ),
    category="local",
    server_type="apache",
    tags=("headers",),
    standards=(
        cwe(693),
        owasp_top10_2021("A05:2021"),
        asvs_5("3.4.7", coverage="partial", note="CSP reporting endpoint configured."),
    ),
    order=364,
)
def find_content_security_policy_missing_reporting_endpoint(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    return unsafe_header_findings(
        config_ast,
        header_name="Content-Security-Policy",
        is_safe_value=content_security_policy_has_reporting_endpoint,
        rule_id=RULE_ID,
        title="Content-Security-Policy missing reporting endpoint",
        description=(
            "Content-Security-Policy is configured without a report-uri or "
            "report-to directive, so policy violations are not reported."
        ),
        recommendation=(
            "Add a CSP report-to or report-uri directive pointing at a "
            "controlled reporting endpoint."
        ),
    )


__all__ = ["find_content_security_policy_missing_reporting_endpoint"]
