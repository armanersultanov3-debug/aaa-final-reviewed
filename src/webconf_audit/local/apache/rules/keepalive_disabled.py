from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.server_directive_utils import (
    configured_value,
    deduplicate_findings_by_location,
    directive_location,
    iter_effective_server_directives,
    virtualhost_label,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.keepalive_disabled"


@rule(
    rule_id=RULE_ID,
    title="KeepAlive is not enabled",
    severity="low",
    description="Apache explicitly disables or misconfigures KeepAlive.",
    recommendation="Set 'KeepAlive On' in the effective Apache scope.",
    category="local",
    server_type="apache",
    order=329,
)
def find_keepalive_disabled(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for context, directive in iter_effective_server_directives(config_ast, "keepalive"):
        if directive is None:
            continue

        if len(directive.args) == 1 and directive.args[0].lower() == "on":
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="KeepAlive is not enabled",
                severity="low",
                description=(
                    f"Apache scope '{virtualhost_label(context)}' sets effective "
                    f"'KeepAlive' to '{configured_value(directive)}' instead of 'On'."
                ),
                recommendation="Set the effective directive to 'KeepAlive On'.",
                location=directive_location(directive),
            )
        )

    return deduplicate_findings_by_location(findings)


__all__ = ["find_keepalive_disabled"]
