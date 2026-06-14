"""Reusable effective scope graph for expanded Nginx ASTs."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
import hashlib
from pathlib import PurePath

from webconf_audit.local.nginx.parser.ast import AstNode, BlockNode, ConfigAst, SourceSpan
from webconf_audit.models import AnalysisIssue


class NginxScopeKind(str, Enum):
    MAIN = "main"
    HTTP = "http"
    SERVER = "server"
    LOCATION = "location"
    IF_IN_LOCATION = "if_in_location"
    LIMIT_EXCEPT = "limit_except"


@dataclass(frozen=True)
class NginxScope:
    scope_id: str
    kind: NginxScopeKind
    parent_id: str | None
    block: BlockNode | None
    selector: str | None
    source: SourceSpan
    complete: bool
    completeness_issues: tuple[str, ...]


@dataclass(frozen=True)
class NginxScopeGraph:
    scopes: tuple[NginxScope, ...]
    root_scope_id: str
    scopes_by_id: dict[str, NginxScope]
    child_scope_ids: dict[str, tuple[str, ...]]
    node_scope_ids: dict[int, str]
    block_scope_ids: dict[int, str]
    scope_nodes: dict[str, tuple[AstNode, ...]]

    def scope_for_node(self, node: AstNode) -> NginxScope:
        return self.scopes_by_id[self.node_scope_ids[id(node)]]

    def scope_for_block(self, block: BlockNode) -> NginxScope:
        scope_id = self.block_scope_ids.get(id(block), self.node_scope_ids[id(block)])
        return self.scopes_by_id[scope_id]

    def parent_chain(self, scope_id: str) -> tuple[NginxScope, ...]:
        chain: list[NginxScope] = []
        current = self.scopes_by_id[scope_id]
        while True:
            chain.append(current)
            if current.parent_id is None:
                break
            current = self.scopes_by_id[current.parent_id]
        return tuple(chain)

    def descendants(self, scope_id: str) -> tuple[NginxScope, ...]:
        descendants: list[NginxScope] = []
        stack = list(reversed(self.child_scope_ids.get(scope_id, ())))
        while stack:
            current_id = stack.pop()
            descendants.append(self.scopes_by_id[current_id])
            stack.extend(reversed(self.child_scope_ids.get(current_id, ())))
        return tuple(descendants)

    def scopes_of_kind(self, kind: NginxScopeKind) -> tuple[NginxScope, ...]:
        return tuple(scope for scope in self.scopes if scope.kind == kind)


def build_scope_graph(
    config_ast: ConfigAst,
    *,
    issues: tuple[AnalysisIssue, ...] | list[AnalysisIssue] = (),
    root_file: str | None = None,
) -> NginxScopeGraph:
    first_source = _graph_root_source(config_ast, root_file=root_file)
    root_scope_id = _make_scope_id(
        parent_id=None,
        kind=NginxScopeKind.MAIN,
        source=first_source,
        ordinal=1,
    )

    scopes: list[NginxScope] = [
        NginxScope(
            scope_id=root_scope_id,
            kind=NginxScopeKind.MAIN,
            parent_id=None,
            block=None,
            selector=None,
            source=first_source,
            complete=True,
            completeness_issues=(),
        )
    ]
    child_scope_ids: dict[str, list[str]] = defaultdict(list)
    node_scope_ids: dict[int, str] = {}
    block_scope_ids: dict[int, str] = {}
    scope_nodes: dict[str, list[AstNode]] = defaultdict(list)
    scope_ordinals: dict[tuple[str, str], int] = defaultdict(int)

    def visit_nodes(nodes: list[AstNode], *, current_scope_id: str) -> None:
        current_scope = scopes_by_id[current_scope_id]
        for node in nodes:
            node_scope_ids[id(node)] = current_scope_id
            scope_nodes[current_scope_id].append(node)
            if not isinstance(node, BlockNode):
                continue

            child_scope_kind = _scope_kind_for_block(node, current_scope.kind)
            if child_scope_kind is None:
                visit_nodes(node.children, current_scope_id=current_scope_id)
                continue

            scope_ordinals[(current_scope_id, child_scope_kind.value)] += 1
            selector = " ".join(node.args) if node.args else None
            child_scope_id = _make_scope_id(
                parent_id=current_scope_id,
                kind=child_scope_kind,
                source=node.source,
                ordinal=scope_ordinals[(current_scope_id, child_scope_kind.value)],
            )
            child_scope_ids[current_scope_id].append(child_scope_id)
            block_scope_ids[id(node)] = child_scope_id
            scopes_by_id[child_scope_id] = NginxScope(
                scope_id=child_scope_id,
                kind=child_scope_kind,
                parent_id=current_scope_id,
                block=node,
                selector=selector,
                source=node.source,
                complete=True,
                completeness_issues=(),
            )
            scopes.append(scopes_by_id[child_scope_id])
            visit_nodes(node.children, current_scope_id=child_scope_id)

    scopes_by_id: dict[str, NginxScope] = {root_scope_id: scopes[0]}
    visit_nodes(config_ast.nodes, current_scope_id=root_scope_id)

    incomplete_by_scope: dict[str, set[str]] = defaultdict(set)
    include_scope_by_location = _include_scope_index(scope_nodes, node_scope_ids)
    for issue in issues:
        affected_scope_id = _affected_scope_id(issue, include_scope_by_location)
        if affected_scope_id is None:
            continue
        incomplete_by_scope[affected_scope_id].add(issue.code)
        for descendant in _descendant_ids(affected_scope_id, child_scope_ids):
            incomplete_by_scope[descendant].add(issue.code)

    finalized_scopes = tuple(
        scope.model_copy(  # type: ignore[attr-defined]
            update={
                "complete": scope.scope_id not in incomplete_by_scope,
                "completeness_issues": tuple(sorted(incomplete_by_scope.get(scope.scope_id, ()))),
            }
        )
        if hasattr(scope, "model_copy")
        else NginxScope(
            scope_id=scope.scope_id,
            kind=scope.kind,
            parent_id=scope.parent_id,
            block=scope.block,
            selector=scope.selector,
            source=scope.source,
            complete=scope.scope_id not in incomplete_by_scope,
            completeness_issues=tuple(sorted(incomplete_by_scope.get(scope.scope_id, ()))),
        )
        for scope in scopes
    )
    finalized_lookup = {scope.scope_id: scope for scope in finalized_scopes}

    return NginxScopeGraph(
        scopes=finalized_scopes,
        root_scope_id=root_scope_id,
        scopes_by_id=finalized_lookup,
        child_scope_ids={
            scope_id: tuple(children)
            for scope_id, children in child_scope_ids.items()
        },
        node_scope_ids=node_scope_ids,
        block_scope_ids=block_scope_ids,
        scope_nodes={
            scope_id: tuple(nodes)
            for scope_id, nodes in scope_nodes.items()
        },
    )


def _graph_root_source(config_ast: ConfigAst, *, root_file: str | None) -> SourceSpan:
    for node in config_ast.nodes:
        return node.source
    return SourceSpan(file_path=root_file, line=1, column=1)


def _scope_kind_for_block(
    block: BlockNode,
    parent_kind: NginxScopeKind,
) -> NginxScopeKind | None:
    if block.name == "http" and parent_kind == NginxScopeKind.MAIN:
        return NginxScopeKind.HTTP
    if block.name == "server" and parent_kind == NginxScopeKind.HTTP:
        return NginxScopeKind.SERVER
    if block.name == "location" and parent_kind in {
        NginxScopeKind.SERVER,
        NginxScopeKind.LOCATION,
    }:
        return NginxScopeKind.LOCATION
    if block.name == "if" and parent_kind == NginxScopeKind.LOCATION:
        return NginxScopeKind.IF_IN_LOCATION
    if block.name == "limit_except" and parent_kind == NginxScopeKind.LOCATION:
        return NginxScopeKind.LIMIT_EXCEPT
    return None


def _make_scope_id(
    *,
    parent_id: str | None,
    kind: NginxScopeKind,
    source: SourceSpan,
    ordinal: int,
) -> str:
    normalized_path = (
        PurePath(source.file_path).as_posix()
        if source.file_path is not None
        else "<unknown>"
    )
    digest = hashlib.sha256(
        f"{parent_id or '<root>'}|{kind.value}|{normalized_path}|{source.line}|{source.column}|{ordinal}".encode(
            "utf-8"
        )
    ).hexdigest()[:16]
    return f"{kind.value}:{digest}"


def _include_scope_index(
    scope_nodes: dict[str, list[AstNode]],
    node_scope_ids: dict[int, str],
) -> dict[tuple[str | None, int], str]:
    index: dict[tuple[str | None, int], str] = {}
    for scope_id, nodes in scope_nodes.items():
        for node in nodes:
            if isinstance(node, BlockNode):
                continue
            if node.name != "include":
                continue
            index[(node.source.file_path, node.source.line)] = node_scope_ids[id(node)]
    return index


def _affected_scope_id(
    issue: AnalysisIssue,
    include_scope_by_location: dict[tuple[str | None, int], str],
) -> str | None:
    metadata = issue.metadata
    if metadata:
        parent_file = metadata.get("include_parent_file")
        parent_line = metadata.get("include_parent_line")
        if isinstance(parent_line, int):
            scope_id = include_scope_by_location.get((parent_file, parent_line))
            if scope_id is not None:
                return scope_id
    if issue.location is None:
        return None
    return include_scope_by_location.get((issue.location.file_path, issue.location.line or 0))


def _descendant_ids(
    scope_id: str,
    child_scope_ids: dict[str, list[str]],
) -> tuple[str, ...]:
    descendants: list[str] = []
    stack = list(reversed(child_scope_ids.get(scope_id, [])))
    while stack:
        current = stack.pop()
        descendants.append(current)
        stack.extend(reversed(child_scope_ids.get(current, [])))
    return tuple(descendants)


__all__ = [
    "NginxScope",
    "NginxScopeGraph",
    "NginxScopeKind",
    "build_scope_graph",
]
