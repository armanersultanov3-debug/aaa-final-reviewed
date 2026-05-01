from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.server_directive_utils import (
    configured_value,
    deduplicate_findings_by_location,
    directive_location,
    iter_effective_server_directives,
    parse_single_positive_int,
    virtualhost_label,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.max_keepalive_requests_too_low"
MIN_REQUESTS = 100


@rule(
    rule_id=RULE_ID,
    title="MaxKeepAliveRequests is too low",
    severity="low",
    description="Apache sets MaxKeepAliveRequests below the CIS recommended floor.",
    recommendation="Set 'MaxKeepAliveRequests' to 100 or greater.",
    category="local",
    server_type="apache",
    order=330,
)
def find_max_keepalive_requests_too_low(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for context, directive in iter_effective_server_directives(
        config_ast,
        "maxkeepaliverequests",
    ):
        if directive is None:
            continue

        value = parse_single_positive_int(directive.args)
        if value is not None and value >= MIN_REQUESTS:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="MaxKeepAliveRequests is too low",
                severity="low",
                description=(
                    f"Apache scope '{virtualhost_label(context)}' sets effective "
                    f"'MaxKeepAliveRequests' to '{configured_value(directive)}', "
                    "which is not 100 or greater."
                ),
                recommendation="Set the effective 'MaxKeepAliveRequests' directive to 100 or greater.",
                location=directive_location(directive),
            )
        )

    return deduplicate_findings_by_location(findings)


__all__ = ["find_max_keepalive_requests_too_low"]
