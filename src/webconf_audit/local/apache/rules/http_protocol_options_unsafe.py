"""Implements rule ``apache.http_protocol_options_unsafe``.

Location: ``src/webconf_audit/local/apache/rules/http_protocol_options_unsafe.py``.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.server_directive_utils import (
    configured_value,
    deduplicate_findings_by_location,
    default_location,
    directive_location,
    iter_effective_server_directives,
    virtualhost_label,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.http_protocol_options_unsafe"
TITLE = "HttpProtocolOptions does not enforce Strict Require1.0"
_REQUIRED_TOKENS = frozenset({"strict", "require1.0"})
_UNSAFE_TOKENS = frozenset({"unsafe", "allow0.9"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=(
        "Apache does not enforce strict HTTP request parsing and HTTP/1.0+ "
        "requests with HttpProtocolOptions."
    ),
    recommendation="Set the effective directive to 'HttpProtocolOptions Strict Require1.0'.",
    category="local",
    server_type="apache",
    order=361,
)
def find_http_protocol_options_unsafe(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for context, directive in iter_effective_server_directives(
        config_ast,
        "httpprotocoloptions",
    ):
        if directive is None:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=TITLE,
                    severity="low",
                    description=(
                        f"Apache scope '{virtualhost_label(context)}' does not define "
                        "an effective 'HttpProtocolOptions Strict Require1.0' directive."
                    ),
                    recommendation=(
                        "Set the effective directive to "
                        "'HttpProtocolOptions Strict Require1.0'."
                    ),
                    location=default_location(config_ast),
                )
            )
            continue

        tokens = {arg.lower() for arg in directive.args}
        unsafe_tokens = sorted(tokens & _UNSAFE_TOKENS)
        missing_tokens = sorted(_REQUIRED_TOKENS - tokens)
        if not unsafe_tokens and not missing_tokens:
            continue

        reason_parts = []
        if unsafe_tokens:
            reason_parts.append("unsafe tokens: " + ", ".join(unsafe_tokens))
        if missing_tokens:
            reason_parts.append("missing tokens: " + ", ".join(missing_tokens))

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    f"Apache scope '{virtualhost_label(context)}' sets effective "
                    f"'HttpProtocolOptions' to '{configured_value(directive)}' "
                    f"({'; '.join(reason_parts)})."
                ),
                recommendation=(
                    "Set the effective directive to "
                    "'HttpProtocolOptions Strict Require1.0'."
                ),
                location=directive_location(directive),
            )
        )

    return deduplicate_findings_by_location(findings)


__all__ = ["find_http_protocol_options_unsafe"]
