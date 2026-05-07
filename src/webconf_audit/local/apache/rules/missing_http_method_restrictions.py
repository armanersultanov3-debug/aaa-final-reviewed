from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    explicit_module_inventory,
    nodes_guarantee_method_restriction,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_http_method_restrictions"
TITLE = "Missing HTTP method restrictions"
DESCRIPTION = (
    "Sensitive Apache Location block does not define an explicit HTTP method "
    "restriction."
)
RECOMMENDATION = (
    "Add a '<LimitExcept ...>' block with 'Require all denied' or an equivalent "
    "'Require method ...' policy for sensitive locations."
)
SENSITIVE_LOCATION_MARKERS = ("/admin", "/login", "/api", "/upload", "/uploads")
LOCATION_BLOCK_NAMES = frozenset({"location", "locationmatch"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=340,
)
def find_missing_http_method_restrictions(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    modules = explicit_module_inventory(config_ast)
    for location in _iter_location_blocks(config_ast.nodes):
        if not _is_sensitive_location(location):
            continue
        if _location_has_method_restriction(location, modules):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=DESCRIPTION,
                recommendation=RECOMMENDATION,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=location.source.file_path,
                    line=location.source.line,
                ),
            )
        )
    return findings


def _iter_location_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheBlockNode]:
    blocks: list[ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            continue
        if node.name.lower() in LOCATION_BLOCK_NAMES:
            blocks.append(node)
        blocks.extend(_iter_location_blocks(node.children))
    return blocks


def _is_sensitive_location(location: ApacheBlockNode) -> bool:
    if not location.args:
        return False
    value = " ".join(location.args).lower()
    return any(marker in value for marker in SENSITIVE_LOCATION_MARKERS)


def _location_has_method_restriction(
    location: ApacheBlockNode,
    modules: frozenset[str],
) -> bool:
    return nodes_guarantee_method_restriction(location.children, modules)


__all__ = ["find_missing_http_method_restrictions"]
