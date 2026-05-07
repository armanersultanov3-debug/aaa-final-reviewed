from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from webconf_audit.local.apache.effective import ApacheVirtualHostContext
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)

TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifversion", "else", "elseif"}
)
AUTHZ_CONTAINER_BLOCKS = frozenset({"requireall", "requireany", "requirenone"})
METHOD_RESTRICTION_BLOCKS = frozenset({"limit", "limitexcept"})
ALL_WRAPPER_BLOCKS = TRANSPARENT_WRAPPER_BLOCKS | frozenset({"ifmodule"})


@dataclass(frozen=True, slots=True)
class MethodPolicyResult:
    has_policy: bool
    unapproved_methods: frozenset[str] = frozenset()


def explicit_module_inventory(
    config_ast: ApacheConfigAst,
) -> frozenset[str]:
    modules: set[str] = set()
    for directive in _iter_loadmodule_directives(config_ast.nodes):
        if len(directive.args) < 1:
            continue
        modules.update(_module_aliases(directive.args[0]))
        if len(directive.args) >= 2:
            modules.update(_module_aliases(directive.args[1]))
    return frozenset(modules)


def module_explicitly_loaded(
    modules: frozenset[str],
    module_token: str,
) -> bool:
    aliases = _module_aliases(module_token)
    return any(alias in modules for alias in aliases)


def ifmodule_matches(
    args: list[str],
    modules: frozenset[str],
) -> bool:
    return _ifmodule_matches(args, modules)


def block_guarantees_ip_restriction(
    block: ApacheBlockNode,
    modules: frozenset[str],
) -> bool:
    return _nodes_guarantee_ip_restriction(block.children, modules)


def nodes_guarantee_method_restriction(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> bool:
    return _nodes_guarantee_method_restriction(nodes, modules)


def nodes_define_method_policy(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> bool:
    return bool(_relevant_method_nodes(nodes, modules))


def block_has_unapproved_allowed_methods(
    block: ApacheBlockNode,
    modules: frozenset[str],
    approved_methods: frozenset[str],
) -> set[str]:
    result = _nodes_method_policy(
        block.children,
        modules,
        approved_methods,
    )
    if not result.has_policy:
        return set()
    return set(result.unapproved_methods)


def matching_location_scopes_for_path(
    config_ast: ApacheConfigAst,
    target_path: str,
    *,
    virtualhost_context: ApacheVirtualHostContext | None = None,
    modules: frozenset[str] = frozenset(),
) -> list[ApacheBlockNode]:
    return [
        block
        for block, _priority in _iter_location_blocks_for_context(
            config_ast.nodes,
            virtualhost_context=virtualhost_context,
            modules=modules,
        )
        if _location_block_matches(block, target_path)
    ]


def effective_location_guarantees_ip_restriction(
    scopes: list[ApacheBlockNode],
    modules: frozenset[str],
) -> bool:
    if not scopes:
        return False

    restricted = False
    for scope in scopes:
        if _location_scope_defines_authz(scope, modules):
            restricted = block_guarantees_ip_restriction(scope, modules)
    return restricted


def iter_enabled_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in iter_enabled_nodes(nodes, modules):
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
    return directives


def iter_enabled_scoped_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in iter_enabled_nodes(nodes, modules):
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
            continue
        if node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
            directives.extend(iter_enabled_scoped_directives(node.children, modules))
    return directives


def has_https_upstream_proxy(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> bool:
    for directive in iter_enabled_scoped_directives(nodes, modules):
        if directive.name.lower() not in {"proxypass", "proxypassmatch"}:
            continue
        if not directive.args:
            continue
        target = directive.args[-1].strip().strip('"').strip("'").lower()
        if target.startswith("https://"):
            return True
    return False


def _iter_loadmodule_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if node.name.lower() == "loadmodule":
                directives.append(node)
            continue

        child_name = node.name.lower()
        if child_name in ALL_WRAPPER_BLOCKS:
            directives.extend(_iter_loadmodule_directives(node.children))
    return directives


def _module_aliases(raw_value: str) -> set[str]:
    value = raw_value.strip().strip('"').strip("'").lower()
    if not value:
        return set()

    file_name = Path(value).name.lower()
    aliases = {value, file_name}
    aliases.update(_normalized_module_aliases(value))
    if file_name != value:
        aliases.update(_normalized_module_aliases(file_name))
    return {alias for alias in aliases if alias}


def _normalized_module_aliases(value: str) -> set[str]:
    normalized = value.removeprefix("!")
    aliases = {normalized}

    if normalized.endswith("_module"):
        bare = normalized.removesuffix("_module")
        aliases.update({bare, f"mod_{bare}.c"})
    elif normalized.startswith("mod_") and normalized.endswith(".c"):
        bare = normalized.removeprefix("mod_").removesuffix(".c")
        aliases.update({bare, f"{bare}_module"})
    elif normalized.startswith("mod_") and normalized.endswith(".so"):
        bare = normalized.removeprefix("mod_").removesuffix(".so")
        aliases.update({bare, f"{bare}_module", f"mod_{bare}.c"})
    elif normalized.endswith(".so"):
        bare = normalized.removesuffix(".so")
        aliases.add(bare)

    return aliases


def iter_enabled_nodes(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> list[ApacheDirectiveNode | ApacheBlockNode]:
    enabled: list[ApacheDirectiveNode | ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            enabled.append(node)
            continue

        name = node.name.lower()
        if name == "ifmodule":
            if _ifmodule_matches(node.args, modules):
                enabled.extend(iter_enabled_nodes(node.children, modules))
            continue

        if name in TRANSPARENT_WRAPPER_BLOCKS:
            enabled.extend(iter_enabled_nodes(node.children, modules))
            continue

        enabled.append(node)
    return enabled


def _ifmodule_matches(
    args: list[str],
    modules: frozenset[str],
) -> bool:
    if not args:
        return False

    token = args[0].strip().strip('"').strip("'")
    negated = token.startswith("!")
    module_token = token[1:] if negated else token
    loaded = module_explicitly_loaded(modules, module_token)

    # When we do not have explicit inventory for a module, keep positive
    # IfModule branches enabled to avoid false negatives on statically-built
    # Apache modules.
    if not loaded and not negated:
        return True

    return not loaded if negated else loaded


def _nodes_guarantee_ip_restriction(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
    *,
    container_name: str = "requireany",
) -> bool:
    relevant = _relevant_authz_nodes(nodes, modules)
    if not relevant:
        return False

    child_results = [_node_guarantees_ip_restriction(node, modules) for node in relevant]
    return _combine_guarantees(child_results, container_name=container_name)


def _nodes_guarantee_method_restriction(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
    *,
    container_name: str = "requireany",
) -> bool:
    relevant = _relevant_method_nodes(nodes, modules)
    if not relevant:
        return False

    child_results = [
        _node_guarantees_method_restriction(node, modules)
        for node in relevant
    ]
    return _combine_guarantees(child_results, container_name=container_name)


def _combine_guarantees(
    child_results: list[bool],
    *,
    container_name: str,
) -> bool:
    if not child_results:
        return False

    if container_name == "requireall":
        return any(child_results)
    if container_name == "requirenone":
        return False
    return all(child_results)


def _node_guarantees_ip_restriction(
    node: ApacheDirectiveNode | ApacheBlockNode,
    modules: frozenset[str],
) -> bool:
    if isinstance(node, ApacheDirectiveNode):
        return _is_require_ip(node) or _is_require_all_denied(node) or _is_legacy_deny_all(node)

    name = node.name.lower()
    if name in AUTHZ_CONTAINER_BLOCKS:
        return _nodes_guarantee_ip_restriction(
            node.children,
            modules,
            container_name=name,
        )
    return False


def _node_guarantees_method_restriction(
    node: ApacheDirectiveNode | ApacheBlockNode,
    modules: frozenset[str],
) -> bool:
    if isinstance(node, ApacheDirectiveNode):
        return _is_require_method(node)

    name = node.name.lower()
    if name in AUTHZ_CONTAINER_BLOCKS:
        return _nodes_guarantee_method_restriction(
            node.children,
            modules,
            container_name=name,
        )
    if name in METHOD_RESTRICTION_BLOCKS:
        return _method_block_guarantees_restriction(node.children, modules)
    return False


def _nodes_guarantee_deny_all(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
    *,
    container_name: str = "requireany",
) -> bool:
    relevant = _relevant_authz_nodes(nodes, modules)
    if not relevant:
        return False

    child_results = [_node_guarantees_deny_all(node, modules) for node in relevant]
    return _combine_guarantees(child_results, container_name=container_name)


def _node_guarantees_deny_all(
    node: ApacheDirectiveNode | ApacheBlockNode,
    modules: frozenset[str],
) -> bool:
    if isinstance(node, ApacheDirectiveNode):
        return _is_require_all_denied(node) or _is_legacy_deny_all(node)

    name = node.name.lower()
    if name in AUTHZ_CONTAINER_BLOCKS:
        return _nodes_guarantee_deny_all(
            node.children,
            modules,
            container_name=name,
        )
    return False


def _nodes_method_policy(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
    approved_methods: frozenset[str],
    *,
    container_name: str = "requireany",
) -> MethodPolicyResult:
    relevant = _relevant_method_nodes(nodes, modules)
    if not relevant:
        return MethodPolicyResult(has_policy=False)

    child_results = [
        _node_method_policy(node, modules, approved_methods)
        for node in relevant
    ]

    if container_name == "requireall":
        policy_children = [result for result in child_results if result.has_policy]
        if not policy_children:
            return MethodPolicyResult(has_policy=False)
        return MethodPolicyResult(
            has_policy=True,
            unapproved_methods=frozenset(
                method
                for result in policy_children
                for method in result.unapproved_methods
            ),
        )

    if container_name == "requirenone" or any(not result.has_policy for result in child_results):
        return MethodPolicyResult(has_policy=False)

    return MethodPolicyResult(
        has_policy=True,
        unapproved_methods=frozenset(
            method
            for result in child_results
            for method in result.unapproved_methods
        ),
    )


def _node_method_policy(
    node: ApacheDirectiveNode | ApacheBlockNode,
    modules: frozenset[str],
    approved_methods: frozenset[str],
) -> MethodPolicyResult:
    if isinstance(node, ApacheDirectiveNode):
        if not _is_require_method(node):
            return MethodPolicyResult(has_policy=False)
        return MethodPolicyResult(
            has_policy=True,
            unapproved_methods=frozenset(
                method.upper()
                for method in node.args[1:]
                if method.upper() not in approved_methods
            ),
        )

    name = node.name.lower()
    if name in AUTHZ_CONTAINER_BLOCKS:
        return _nodes_method_policy(
            node.children,
            modules,
            approved_methods,
            container_name=name,
        )
    if name == "limitexcept" and _nodes_guarantee_deny_all(node.children, modules):
        return MethodPolicyResult(
            has_policy=True,
            unapproved_methods=frozenset(
                method.upper()
                for method in node.args
                if method.upper() not in approved_methods
            ),
        )
    return MethodPolicyResult(has_policy=False)


def _method_block_guarantees_restriction(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> bool:
    if _nodes_guarantee_deny_all(nodes, modules):
        return True

    for node in iter_enabled_nodes(nodes, modules):
        if not isinstance(node, ApacheBlockNode):
            continue
        name = node.name.lower()
        if name in AUTHZ_CONTAINER_BLOCKS and _nodes_guarantee_method_restriction(
            node.children,
            modules,
            container_name=name,
        ):
            return True
        if name in METHOD_RESTRICTION_BLOCKS and _method_block_guarantees_restriction(
            node.children,
            modules,
        ):
            return True
    return False


def _relevant_authz_nodes(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> list[ApacheDirectiveNode | ApacheBlockNode]:
    relevant: list[ApacheDirectiveNode | ApacheBlockNode] = []
    for node in iter_enabled_nodes(nodes, modules):
        if isinstance(node, ApacheDirectiveNode):
            if (
                _is_require_ip(node)
                or _is_require_all_denied(node)
                or _is_legacy_deny_all(node)
                or _is_require_all_granted(node)
            ):
                relevant.append(node)
            continue

        if node.name.lower() in AUTHZ_CONTAINER_BLOCKS:
            relevant.append(node)
    return relevant


def _relevant_method_nodes(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> list[ApacheDirectiveNode | ApacheBlockNode]:
    relevant: list[ApacheDirectiveNode | ApacheBlockNode] = []
    for node in iter_enabled_nodes(nodes, modules):
        if isinstance(node, ApacheDirectiveNode):
            if _is_require_method(node) or _is_require_all_granted(node):
                relevant.append(node)
            continue

        if node.name.lower() in AUTHZ_CONTAINER_BLOCKS | METHOD_RESTRICTION_BLOCKS:
            relevant.append(node)
    return relevant


def _location_scope_defines_authz(
    block: ApacheBlockNode,
    modules: frozenset[str],
) -> bool:
    return bool(_relevant_authz_nodes(block.children, modules))


def _location_block_matches(block: ApacheBlockNode, target_path: str) -> bool:
    if not block.args:
        return False

    name = block.name.lower()
    raw_path = block.args[0].strip().strip('"').strip("'")
    if name == "location":
        if raw_path == "/":
            return True
        lowered_target = target_path.lower()
        lowered_path = raw_path.lower()
        return lowered_target == lowered_path or lowered_target.startswith(
            lowered_path.rstrip("/") + "/"
        )

    if name != "locationmatch":
        return False

    import re  # noqa: PLC0415

    try:
        return re.search(raw_path, target_path) is not None
    except re.error:
        return False


def _iter_location_blocks_for_context(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    modules: frozenset[str],
    source_priority: int = 0,
) -> list[tuple[ApacheBlockNode, int]]:
    blocks: list[tuple[ApacheBlockNode, int]] = []

    for node in iter_enabled_nodes(nodes, modules):
        if not isinstance(node, ApacheBlockNode):
            continue

        name = node.name.lower()
        if name == "virtualhost":
            if virtualhost_context is not None and node is virtualhost_context.node:
                blocks.extend(
                    _iter_location_blocks_for_context(
                        node.children,
                        virtualhost_context=virtualhost_context,
                        modules=modules,
                        source_priority=1,
                    )
                )
            continue

        if name in {"location", "locationmatch"}:
            blocks.append((node, source_priority))

        blocks.extend(
            _iter_location_blocks_for_context(
                node.children,
                virtualhost_context=virtualhost_context,
                modules=modules,
                source_priority=source_priority,
            )
        )

    blocks.sort(
        key=lambda item: (
            len(item[0].args[0]) if item[0].args else 0,
            0 if item[0].name.lower() == "location" else 1,
            item[1],
        )
    )
    return blocks


def _is_require_ip(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "require"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "ip"
    )


def _is_require_method(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "require"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "method"
    )


def _is_require_all_denied(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "require"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "all"
        and directive.args[1].lower() in {"denied", "deny"}
    )


def _is_require_all_granted(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "require"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "all"
        and directive.args[1].lower() == "granted"
    )


def _is_legacy_deny_all(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "deny"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "from"
        and directive.args[1].lower() == "all"
    )


__all__ = [
    "MethodPolicyResult",
    "block_guarantees_ip_restriction",
    "block_has_unapproved_allowed_methods",
    "effective_location_guarantees_ip_restriction",
    "explicit_module_inventory",
    "has_https_upstream_proxy",
    "ifmodule_matches",
    "iter_enabled_directives",
    "iter_enabled_nodes",
    "iter_enabled_scoped_directives",
    "matching_location_scopes_for_path",
    "module_explicitly_loaded",
    "nodes_define_method_policy",
    "nodes_guarantee_method_restriction",
]
