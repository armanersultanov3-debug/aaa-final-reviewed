from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.effective import ApacheVirtualHostContext, extract_virtualhost_contexts
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    effective_location_guarantees_method_restriction,
    explicit_module_inventory,
    iter_enabled_nodes,
    matching_location_scopes_for_path,
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
    seen: set[tuple[str | None, int | None]] = set()

    for virtualhost_context, nodes in _iter_context_nodes(config_ast):
        for location in _iter_location_blocks(nodes, modules):
            if not _is_sensitive_location(location):
                continue
            if _location_has_effective_method_restriction(
                config_ast,
                location,
                virtualhost_context,
                modules,
            ):
                continue

            key = (location.source.file_path, location.source.line)
            if key in seen:
                continue
            seen.add(key)
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


def _iter_context_nodes(
    config_ast: ApacheConfigAst,
) -> list[tuple[ApacheVirtualHostContext | None, list[ApacheDirectiveNode | ApacheBlockNode]]]:
    contexts: list[
        tuple[ApacheVirtualHostContext | None, list[ApacheDirectiveNode | ApacheBlockNode]]
    ] = [(None, config_ast.nodes)]
    contexts.extend(
        (context, context.node.children)
        for context in extract_virtualhost_contexts(config_ast)
    )
    return contexts


def _iter_location_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> list[ApacheBlockNode]:
    blocks: list[ApacheBlockNode] = []
    for node in iter_enabled_nodes(nodes, modules):
        if isinstance(node, ApacheDirectiveNode):
            continue
        if node.name.lower() == "virtualhost":
            continue
        if node.name.lower() in LOCATION_BLOCK_NAMES:
            blocks.append(node)
        blocks.extend(_iter_location_blocks(node.children, modules))
    return blocks


def _is_sensitive_location(location: ApacheBlockNode) -> bool:
    if not location.args:
        return False
    value = " ".join(location.args).lower()
    return any(marker in value for marker in SENSITIVE_LOCATION_MARKERS)


def _location_has_effective_method_restriction(
    config_ast: ApacheConfigAst,
    location: ApacheBlockNode,
    virtualhost_context: ApacheVirtualHostContext | None,
    modules: frozenset[str],
) -> bool:
    target_path = _location_target_path(location)
    if target_path is None:
        return nodes_guarantee_method_restriction(location.children, modules)

    scopes = matching_location_scopes_for_path(
        config_ast,
        target_path,
        virtualhost_context=virtualhost_context,
        modules=modules,
    )
    if not scopes:
        return nodes_guarantee_method_restriction(location.children, modules)

    return effective_location_guarantees_method_restriction(scopes, modules)


def _location_target_path(location: ApacheBlockNode) -> str | None:
    if not location.args:
        return None

    raw_value = " ".join(location.args).lower()
    for marker in SENSITIVE_LOCATION_MARKERS:
        if marker in raw_value:
            return marker
    return None


__all__ = ["find_missing_http_method_restrictions"]
