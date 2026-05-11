from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    extract_virtualhost_contexts,
    iter_directory_blocks_for_context,
)
from webconf_audit.local.apache.path_matching import (
    directory_path_covers,
    path_match_specificity,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    explicit_module_inventory,
    iter_enabled_nodes,
    iter_enabled_scoped_directives,
)
from webconf_audit.local.apache.rules._redirect_scope_utils import (
    is_redirect_only_virtualhost,
)
from webconf_audit.local.apache.rules.server_directive_utils import virtualhost_label
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule
from webconf_audit.standards import owasp_top10_2021

RULE_ID = "apache.directory_without_allowoverride"
_TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)


@dataclass(frozen=True, slots=True)
class _DirectoryScope:
    block: ApacheBlockNode
    path: Path
    source_priority: int


@rule(
    rule_id=RULE_ID,
    title="Directory block lacks explicit AllowOverride",
    severity="low",
    description=(
        "This non-root Directory block does not set AllowOverride explicitly. "
        "CIS Apache expects each Directory scope below the OS-root baseline to "
        "declare its own AllowOverride policy."
    ),
    recommendation=(
        "Set AllowOverride explicitly for each non-root Directory block, "
        "preferably 'AllowOverride None' or a narrow category list."
    ),
    category="local",
    server_type="apache",
    standards=(
        owasp_top10_2021("A05:2021"),
        StandardReference(
            standard="CIS",
            reference="Apache HTTP Server 2.4 v2.3.0 §4.4",
            url="https://www.cisecurity.org/benchmark/apache_http_server",
            note=(
                "Non-root Directory scopes should declare AllowOverride "
                "explicitly; value policy is paired with "
                "apache.allowoverride_not_none."
            ),
        ),
    ),
    order=303,
)
def find_directory_without_allowoverride(config_ast: ApacheConfigAst) -> list[Finding]:
    modules = explicit_module_inventory(config_ast)
    contexts = [
        context
        for context in extract_virtualhost_contexts(config_ast)
        if _context_is_enabled(config_ast, context, modules)
    ]

    findings: list[Finding] = _findings_for_context(
        config_ast,
        virtualhost_context=None,
        modules=modules,
    )
    if not contexts:
        return findings

    for context in contexts:
        if _is_redirect_only_context(context, modules):
            continue
        findings.extend(
            _findings_for_context(
                config_ast,
                virtualhost_context=context,
                modules=modules,
            )
        )
    return findings


def _findings_for_context(
    config_ast: ApacheConfigAst,
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    modules: frozenset[str],
) -> list[Finding]:
    findings: list[Finding] = []
    directory_scopes = _collect_directory_scopes_for_context(
        config_ast,
        virtualhost_context=virtualhost_context,
        modules=modules,
    )
    server_allowoverride = _effective_server_allowoverride_directive(
        config_ast.nodes,
        virtualhost_context=virtualhost_context,
        modules=modules,
    )

    for scope in directory_scopes:
        if virtualhost_context is not None and scope.source_priority == 0:
            continue
        if _is_os_root_directory(scope.block):
            continue
        if _effective_directory_allowoverride_directive(
            scope,
            directory_scopes,
            server_allowoverride=server_allowoverride,
            modules=modules,
        ) is not None:
            continue

        findings.append(_make_finding(scope.block, virtualhost_context))

    return findings


def _make_finding(
    block: ApacheBlockNode,
    virtualhost_context: ApacheVirtualHostContext | None,
) -> Finding:
    metadata: dict[str, object] = {"directory_path": block.args[0]}
    if virtualhost_context is not None:
        metadata["scope_name"] = virtualhost_label(virtualhost_context)

    return Finding(
        rule_id=RULE_ID,
        title="Directory block lacks explicit AllowOverride",
        severity="low",
        description=(
            "This non-root Directory block does not set AllowOverride "
            "explicitly. CIS Apache expects each Directory scope below "
            "the OS-root baseline to declare its own AllowOverride "
            "policy."
        ),
        recommendation=(
            "Set AllowOverride explicitly for each non-root Directory "
            "block, preferably 'AllowOverride None' or a narrow "
            "category list."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=block.source.file_path,
            line=block.source.line,
        ),
        metadata=metadata,
    )


def _effective_server_allowoverride_directive(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    modules: frozenset[str],
) -> ApacheDirectiveNode | None:
    effective: ApacheDirectiveNode | None = None

    for directive in _iter_server_scope_directives(nodes, modules=modules):
        if directive.name.lower() == "allowoverride":
            effective = directive

    if virtualhost_context is not None:
        for directive in iter_enabled_scoped_directives(
            virtualhost_context.node.children,
            modules,
        ):
            if directive.name.lower() == "allowoverride":
                effective = directive

    return effective


def _effective_directory_allowoverride_directive(
    target_scope: _DirectoryScope,
    all_scopes: list[_DirectoryScope],
    *,
    server_allowoverride: ApacheDirectiveNode | None,
    modules: frozenset[str],
) -> ApacheDirectiveNode | None:
    effective = server_allowoverride

    for scope in _covering_directory_scopes(target_scope, all_scopes):
        directive = _find_allowoverride_directive(scope.block, modules)
        if directive is not None:
            effective = directive

    return effective


def _covering_directory_scopes(
    target_scope: _DirectoryScope,
    all_scopes: list[_DirectoryScope],
) -> list[_DirectoryScope]:
    covering = [
        scope
        for scope in all_scopes
        if directory_path_covers(
            target_scope.path,
            scope.path,
            resolve=True,
            case_sensitive=False,
        )
    ]
    covering.sort(
        key=lambda scope: (
            path_match_specificity(
                scope.path,
                resolve=True,
                case_sensitive=False,
            ),
            scope.source_priority,
        )
    )
    return covering


def _find_allowoverride_directive(
    block: ApacheBlockNode,
    modules: frozenset[str],
) -> ApacheDirectiveNode | None:
    winner: ApacheDirectiveNode | None = None
    for directive in iter_enabled_scoped_directives(block.children, modules):
        if directive.name.lower() == "allowoverride":
            winner = directive
    return winner


def _iter_server_scope_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    modules: frozenset[str],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in iter_enabled_nodes(nodes, modules):
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
            continue
        if node.name.lower() == "virtualhost":
            continue
        if node.name.lower() in _TRANSPARENT_WRAPPER_BLOCKS:
            directives.extend(
                _iter_server_scope_directives(node.children, modules=modules)
            )
    return directives


def _collect_directory_scopes_for_context(
    config_ast: ApacheConfigAst,
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    modules: frozenset[str],
) -> list[_DirectoryScope]:
    enabled_block_ids = _enabled_directory_block_ids_for_context(
        config_ast.nodes,
        virtualhost_context=virtualhost_context,
        modules=modules,
    )
    scopes: list[_DirectoryScope] = []

    for block, source_priority in iter_directory_blocks_for_context(
        config_ast,
        virtualhost_context=virtualhost_context,
    ):
        if id(block) not in enabled_block_ids:
            continue

        dir_path = _directory_path(block)
        if dir_path is None:
            continue

        scopes.append(
            _DirectoryScope(
                block=block,
                path=dir_path,
                source_priority=source_priority,
            )
        )

    return scopes


def _enabled_directory_block_ids_for_context(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    modules: frozenset[str],
    source_priority: int = 0,
) -> set[int]:
    block_ids: set[int] = set()

    for node in iter_enabled_nodes(nodes, modules):
        if not isinstance(node, ApacheBlockNode):
            continue

        name = node.name.lower()
        if name == "virtualhost":
            if virtualhost_context is not None and node is virtualhost_context.node:
                block_ids.update(
                    _enabled_directory_block_ids_for_context(
                        node.children,
                        virtualhost_context=virtualhost_context,
                        modules=modules,
                        source_priority=1,
                    )
                )
            continue

        if name == "directory":
            block_ids.add(id(node))

        block_ids.update(
            _enabled_directory_block_ids_for_context(
                node.children,
                virtualhost_context=virtualhost_context,
                modules=modules,
                source_priority=source_priority,
            )
        )

    return block_ids


def _directory_path(block: ApacheBlockNode) -> Path | None:
    if not block.args:
        return None

    raw_path = block.args[0]
    if raw_path.startswith("~"):
        return None

    path = Path(raw_path)
    if path.is_absolute():
        return path.resolve()

    source_file_path = block.source.file_path
    if source_file_path is None:
        return path.resolve()

    return (Path(source_file_path).parent / path).resolve()


def _context_is_enabled(
    config_ast: ApacheConfigAst,
    context: ApacheVirtualHostContext,
    modules: frozenset[str],
) -> bool:
    return any(node is context.node for node in iter_enabled_nodes(config_ast.nodes, modules))


def _is_os_root_directory(block: ApacheBlockNode) -> bool:
    return bool(block.args) and block.args[0] == "/"


def _is_redirect_only_context(
    context: ApacheVirtualHostContext,
    modules: frozenset[str],
) -> bool:
    if is_redirect_only_virtualhost(context, modules):
        return True

    pruned_context = ApacheVirtualHostContext(
        server_name=context.server_name,
        server_aliases=context.server_aliases,
        listen_address=context.listen_address,
        node=_without_directory_children(context.node),
        optional_ancestor_names=context.optional_ancestor_names,
        listen_addresses=context.listen_addresses,
    )
    return is_redirect_only_virtualhost(pruned_context, modules)


def _without_directory_children(block: ApacheBlockNode) -> ApacheBlockNode:
    children: list[ApacheDirectiveNode | ApacheBlockNode] = []
    for child in block.children:
        if isinstance(child, ApacheDirectiveNode):
            children.append(child)
            continue

        if child.name.lower() == "directory":
            continue
        children.append(_without_directory_children(child))

    return ApacheBlockNode(
        name=block.name,
        args=list(block.args),
        children=children,
        source=block.source,
    )


__all__ = ["find_directory_without_allowoverride"]
