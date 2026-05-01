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

RULE_ID = "apache.keepalive_timeout_too_high"
MAX_TIMEOUT_SECONDS = 15


@rule(
    rule_id=RULE_ID,
    title="KeepAliveTimeout is too high",
    severity="low",
    description="Apache sets KeepAliveTimeout above the CIS recommended limit.",
    recommendation="Set 'KeepAliveTimeout' to a positive value of 15 seconds or less.",
    category="local",
    server_type="apache",
    order=331,
)
def find_keepalive_timeout_too_high(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for context, directive in iter_effective_server_directives(
        config_ast,
        "keepalivetimeout",
    ):
        if directive is None:
            continue

        value = parse_single_positive_int(directive.args)
        if value is not None and value <= MAX_TIMEOUT_SECONDS:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="KeepAliveTimeout is too high",
                severity="low",
                description=(
                    f"Apache scope '{virtualhost_label(context)}' sets effective "
                    f"'KeepAliveTimeout' to '{configured_value(directive)}', which "
                    "is not a positive value of 15 seconds or less."
                ),
                recommendation=(
                    "Set the effective 'KeepAliveTimeout' directive to a positive "
                    "value greater than 0 and 15 seconds or less."
                ),
                location=directive_location(directive),
            )
        )

    return deduplicate_findings_by_location(findings)


__all__ = ["find_keepalive_timeout_too_high"]
