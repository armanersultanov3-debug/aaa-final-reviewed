from __future__ import annotations

import re

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdCondition,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import default_location, iter_all_nodes
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.missing_http_method_restrictions"
DANGEROUS_METHODS = frozenset(
    {"TRACE", "PUT", "DELETE", "CONNECT", "PATCH", "PROPFIND"},
)


@rule(
    rule_id=RULE_ID,
    title="Missing HTTP method restrictions",
    severity="low",
    description=(
        "Lighttpd does not define an explicit deny policy for dangerous HTTP "
        "methods."
    ),
    recommendation=(
        "Add a request-method conditional that denies methods such as TRACE, "
        "PUT, DELETE, CONNECT, PATCH, and PROPFIND."
    ),
    category="local",
    server_type="lighttpd",
    order=417,
)
def find_missing_http_method_restrictions(
    config_ast: LighttpdConfigAst,
) -> list[Finding]:
    covered = _covered_dangerous_methods(config_ast)
    missing = DANGEROUS_METHODS - covered
    if not missing:
        return []
    return [
        finding_from_rule(
            find_missing_http_method_restrictions,
            location=default_location(config_ast),
            description=(
                "Lighttpd does not define an explicit deny policy for dangerous "
                f"HTTP method(s): {', '.join(sorted(missing))}."
            ),
        )
    ]


def _covered_dangerous_methods(config_ast: LighttpdConfigAst) -> set[str]:
    covered: set[str] = set()
    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdBlockNode):
            continue
        if not _block_denies_access(node):
            continue
        covered.update(_methods_from_condition(node.condition))
    return covered


def _block_denies_access(block: LighttpdBlockNode) -> bool:
    return any(
        isinstance(child, LighttpdAssignmentNode)
        and child.name == "url.access-deny"
        and '""' in child.value
        for child in block.children
    )


def _methods_from_condition(condition: LighttpdCondition | None) -> set[str]:
    if condition is None or condition.variable != '$HTTP["request-method"]':
        return set()
    if condition.operator not in {"==", "=~"}:
        return set()
    value = condition.value.upper()
    return {
        method
        for method in DANGEROUS_METHODS
        if re.search(rf"\b{re.escape(method)}\b", value)
    }


__all__ = ["find_missing_http_method_restrictions"]
