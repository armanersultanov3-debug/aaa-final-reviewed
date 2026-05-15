"""Implements rule ``apache.timeout_keepalive_default_policy``.

Location: ``src/webconf_audit/local/apache/rules/timeout_keepalive_default_policy.py``.
"""

from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.server_directive_utils import (
    default_location,
    virtualhost_label,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.timeout_keepalive_default_policy"
TITLE = "Timeout and keepalive defaults are not pinned"
DESCRIPTION = (
    "Apache relies on default Timeout / KeepAlive policy instead of making the "
    "server-scope request-connection posture explicit."
)
RECOMMENDATION = (
    "Set explicit values for Timeout, KeepAlive, MaxKeepAliveRequests, and "
    "KeepAliveTimeout in every active Apache scope."
)
_REQUIRED_DIRECTIVES = (
    "timeout",
    "keepalive",
    "maxkeepaliverequests",
    "keepalivetimeout",
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=375,
)
def find_timeout_keepalive_default_policy(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    contexts = [None, *extract_virtualhost_contexts(config_ast)]

    for context in contexts:
        effective = build_server_effective_config(
            config_ast,
            virtualhost_context=context,
        ).directives
        missing = [name for name in _REQUIRED_DIRECTIVES if name not in effective]
        if not missing:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    f"Apache scope '{virtualhost_label(context)}' relies on "
                    f"default policy for: {', '.join(missing)}."
                ),
                recommendation=RECOMMENDATION,
                location=_scope_location(config_ast, context),
            )
        )

    return findings


def _scope_location(
    config_ast: ApacheConfigAst,
    context: ApacheVirtualHostContext | None,
 ) -> SourceLocation | None:
    if context is None:
        return default_location(config_ast)
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=context.node.source.file_path,
        line=context.node.source.line,
    )


__all__ = ["find_timeout_keepalive_default_policy"]
