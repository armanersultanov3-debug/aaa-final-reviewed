from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.effective_directive_check import (
    iter_vhosts_missing_directive,
)
from webconf_audit.local.apache.rules.server_directive_utils import (
    default_location,
    virtualhost_label,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.error_log_missing"
TITLE = "Missing ErrorLog directive"
DESCRIPTION = (
    "Apache config does not define an 'ErrorLog' directive for the applicable "
    "server scope."
)
RECOMMENDATION = (
    "Add an 'ErrorLog' directive at the global server level or within each "
    "affected VirtualHost to establish an error logging baseline."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=306,
)
def find_error_log_missing(config_ast: ApacheConfigAst) -> list[Finding]:
    virtualhosts = extract_virtualhost_contexts(config_ast)
    if not virtualhosts:
        if build_server_effective_config(config_ast).directives.get("errorlog") is not None:
            return []
        return [
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=DESCRIPTION,
                recommendation=RECOMMENDATION,
                location=default_location(config_ast),
            )
        ]

    return [
        _build_virtualhost_finding(context)
        for context in iter_vhosts_missing_directive(config_ast, "errorlog")
    ]


def _build_virtualhost_finding(context: ApacheVirtualHostContext) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="low",
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=context.node.source.file_path,
            line=context.node.source.line,
        ),
        metadata={"scope_name": virtualhost_label(context)},
    )


__all__ = ["find_error_log_missing"]
