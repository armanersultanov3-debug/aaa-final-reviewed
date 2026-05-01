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

RULE_ID = "apache.limit_request_line_too_high"
MAX_REQUEST_LINE_BYTES = 8190


@rule(
    rule_id=RULE_ID,
    title="LimitRequestLine is too high",
    severity="low",
    description="Apache sets LimitRequestLine above the CIS recommended limit.",
    recommendation="Set 'LimitRequestLine' to a positive value of 8190 bytes or less.",
    category="local",
    server_type="apache",
    order=332,
)
def find_limit_request_line_too_high(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for context, directive in iter_effective_server_directives(
        config_ast,
        "limitrequestline",
    ):
        if directive is None:
            continue

        value = parse_single_positive_int(directive.args)
        if value is not None and value <= MAX_REQUEST_LINE_BYTES:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="LimitRequestLine is too high",
                severity="low",
                description=(
                    f"Apache scope '{virtualhost_label(context)}' sets effective "
                    f"'LimitRequestLine' to '{configured_value(directive)}', which "
                    "is not a positive value of 8190 bytes or less."
                ),
                recommendation="Set the effective 'LimitRequestLine' directive to 8190 bytes or less.",
                location=directive_location(directive),
            )
        )

    return deduplicate_findings_by_location(findings)


__all__ = ["find_limit_request_line_too_high"]
