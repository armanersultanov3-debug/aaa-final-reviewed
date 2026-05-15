"""Implements rule ``apache.modsecurity_crs_not_configured``.

Location: ``src/webconf_audit/local/apache/rules/modsecurity_crs_not_configured.py``.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._modsecurity_inventory_utils import (
    find_modsecurity_inventory_source,
    has_crs_inventory,
    has_modsecurity_inventory,
)
from webconf_audit.local.apache.rules._policy_semantics_utils import explicit_module_inventory
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.modsecurity_crs_not_configured"
TITLE = "ModSecurity CRS inventory is not configured"
DESCRIPTION = (
    "Apache enables ModSecurity inventory but does not include OWASP CRS files."
)
RECOMMENDATION = (
    "Include OWASP CRS setup and rules files, such as 'crs-setup.conf' and "
    "the CRS 'rules/*.conf' bundle."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=372,
    tags=("waf",),
)
def find_modsecurity_crs_not_configured(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    modules = explicit_module_inventory(config_ast)
    if not has_modsecurity_inventory(config_ast.nodes, modules):
        return []
    if has_crs_inventory(config_ast.nodes, modules):
        return []

    source = find_modsecurity_inventory_source(config_ast.nodes, modules)
    return [
        Finding(
            rule_id=RULE_ID,
            title=TITLE,
            severity="low",
            description=DESCRIPTION,
            recommendation=RECOMMENDATION,
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=source.file_path if source is not None else None,
                line=source.line if source is not None else None,
            ),
        )
    ]


__all__ = ["find_modsecurity_crs_not_configured"]
