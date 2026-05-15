"""Implements rule ``nginx.alias_traversal_classic_pattern``.

Location: ``src/webconf_audit/local/nginx/rules/alias_traversal_classic_pattern.py``.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, find_child_directives, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cwe, owasp_top10_2021

RULE_ID = "nginx.alias_traversal_classic_pattern"
TITLE = "Alias traversal classic path pattern"
DESCRIPTION = (
    "A prefix location without a trailing slash uses an alias path with a "
    "trailing slash. This is the classic Gixy alias traversal shape."
)
RECOMMENDATION = (
    "Align the location and alias slash semantics so both either end with '/' "
    "or both omit it for the intended mapping."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("paths",),
    standards=(
        cwe(22),
        owasp_top10_2021("A01:2021"),
    ),
    order=276,
)
def find_alias_traversal_classic_pattern(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "location":
            continue
        location_path = _location_prefix_path(node)
        if location_path is None or location_path.endswith("/"):
            continue
        for alias_node in find_child_directives(node, "alias"):
            if not alias_node.args or not alias_node.args[0].endswith("/"):
                continue
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=TITLE,
                    severity="medium",
                    description=DESCRIPTION,
                    recommendation=RECOMMENDATION,
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=alias_node.source.file_path,
                        line=alias_node.source.line,
                    ),
                )
            )

    return findings


def _location_prefix_path(location_block: BlockNode) -> str | None:
    if not location_block.args:
        return None
    modifier = location_block.args[0]
    if modifier == "^~" and len(location_block.args) > 1:
        return location_block.args[1]
    if modifier in {"=", "~", "~*"}:
        return None
    return modifier


__all__ = ["find_alias_traversal_classic_pattern"]
