"""apache.timeout_too_high -- Timeout is too high."""

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

RULE_ID = "apache.timeout_too_high"
MAX_TIMEOUT_SECONDS = 10


@rule(
    rule_id=RULE_ID,
    title="Timeout is too high",
    severity="low",
    description="Apache sets Timeout above the CIS recommended limit.",
    recommendation="Set 'Timeout' to a positive value of 10 seconds or less.",
    category="local",
    server_type="apache",
    order=328,
)
def find_timeout_too_high(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for context, directive in iter_effective_server_directives(config_ast, "timeout"):
        if directive is None:
            continue

        value = parse_single_positive_int(directive.args)
        if value is not None and value <= MAX_TIMEOUT_SECONDS:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Timeout is too high",
                severity="low",
                description=(
                    f"Apache scope '{virtualhost_label(context)}' sets effective "
                    f"'Timeout' to '{configured_value(directive)}', which is not a "
                    "positive value of 10 seconds or less."
                ),
                recommendation="Set the effective 'Timeout' directive to 10 seconds or less.",
                location=directive_location(directive),
            )
        )

    return deduplicate_findings_by_location(findings)


__all__ = ["find_timeout_too_high"]
