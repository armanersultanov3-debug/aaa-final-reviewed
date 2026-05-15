"""Implements rule ``apache.modsecurity_module_missing``.

Location: ``src/webconf_audit/local/apache/rules/modsecurity_module_missing.py``.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._modsecurity_inventory_utils import (
    has_modsecurity_inventory,
)
from webconf_audit.local.apache.rules._policy_semantics_utils import explicit_module_inventory
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.modsecurity_module_missing"
TITLE = "ModSecurity module inventory is missing"
DESCRIPTION = (
    "Apache config does not show ModSecurity module or package inventory."
)
RECOMMENDATION = (
    "Load 'security2_module' or include the package-provided ModSecurity "
    "configuration so the WAF inventory is visible in Apache config."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=371,
    tags=("waf",),
)
def find_modsecurity_module_missing(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    modules = explicit_module_inventory(config_ast)
    if has_modsecurity_inventory(config_ast.nodes, modules):
        return []

    source = config_ast.nodes[0].source if config_ast.nodes else None
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


__all__ = ["find_modsecurity_module_missing"]
