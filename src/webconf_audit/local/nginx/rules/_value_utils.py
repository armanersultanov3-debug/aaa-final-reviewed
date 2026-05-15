"""Internal helpers for the value utils rule family.

Location: ``src/webconf_audit/local/nginx/rules/_value_utils.py``.
"""

from __future__ import annotations

import re

from webconf_audit.local.nginx.parser.ast import (
    AstNode,
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
)

_DURATION_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>ms|s|m|h|d)?$", re.IGNORECASE)
_SIZE_RE = re.compile(r"^(?P<value>\d+)(?P<unit>[kmg])?$", re.IGNORECASE)

_DURATION_MULTIPLIERS = {
    None: 1.0,
    "ms": 0.001,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
}

_SIZE_MULTIPLIERS = {
    None: 1,
    "k": 1024,
    "m": 1024 * 1024,
    "g": 1024 * 1024 * 1024,
}


def parse_duration_seconds(value: str) -> float | None:
    match = _DURATION_RE.match(value)
    if match is None:
        return None
    number = float(match.group("value"))
    unit = match.group("unit")
    multiplier = _DURATION_MULTIPLIERS[unit.lower() if unit else None]
    return number * multiplier


def parse_size_bytes(value: str) -> int | None:
    match = _SIZE_RE.match(value)
    if match is None:
        return None
    number = int(match.group("value"))
    unit = match.group("unit")
    multiplier = _SIZE_MULTIPLIERS[unit.lower() if unit else None]
    return number * multiplier


def iter_direct_child_directives(
    config_ast: ConfigAst,
    directive_name: str,
    *,
    block_names: set[str],
) -> list[tuple[DirectiveNode, BlockNode]]:
    matches: list[tuple[DirectiveNode, BlockNode]] = []

    def walk_blocks(nodes: list[object]) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue
            if node.name in block_names:
                matches.extend(
                    (child, node)
                    for child in node.children
                    if isinstance(child, DirectiveNode) and child.name == directive_name
                )
            walk_blocks(node.children)

    walk_blocks(config_ast.nodes)
    return matches


def iter_last_direct_child_directives(
    config_ast: ConfigAst,
    directive_name: str,
    *,
    block_names: set[str],
) -> list[tuple[DirectiveNode, BlockNode]]:
    matches: list[tuple[DirectiveNode, BlockNode]] = []

    def walk_blocks(nodes: list[object]) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue
            if node.name in block_names:
                directives = [
                    child
                    for child in node.children
                    if isinstance(child, DirectiveNode) and child.name == directive_name
                ]
                if directives:
                    matches.append((directives[-1], node))
            walk_blocks(node.children)

    walk_blocks(config_ast.nodes)
    return matches


def iter_server_blocks_with_http_directives(
    config_ast: ConfigAst,
    directive_names: set[str],
) -> list[tuple[BlockNode, dict[str, list[DirectiveNode]]]]:
    servers: list[tuple[BlockNode, dict[str, list[DirectiveNode]]]] = []

    def walk(
        nodes: list[AstNode],
        inherited_directives: dict[str, list[DirectiveNode]],
    ) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue

            current_directives = inherited_directives
            if node.name == "http":
                current_directives = dict(inherited_directives)
                for directive_name in directive_names:
                    current_directives[directive_name] = find_child_directives(
                        node,
                        directive_name,
                    )

            if node.name == "server":
                servers.append((node, current_directives))
                continue

            walk(node.children, current_directives)

    walk(config_ast.nodes, {})
    return servers


def iter_blocks_with_inherited_directives(
    config_ast: ConfigAst,
    directive_names: set[str],
    *,
    block_names: set[str],
) -> list[tuple[BlockNode, dict[str, list[DirectiveNode]]]]:
    blocks: list[tuple[BlockNode, dict[str, list[DirectiveNode]]]] = []

    def walk(
        nodes: list[AstNode],
        inherited_directives: dict[str, list[DirectiveNode]],
    ) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue

            current_directives = inherited_directives
            if node.name in block_names:
                blocks.append((node, inherited_directives))
                current_directives = dict(inherited_directives)
                for directive_name in directive_names:
                    local_directives = find_child_directives(node, directive_name)
                    if local_directives:
                        current_directives[directive_name] = local_directives

            walk(node.children, current_directives)

    walk(config_ast.nodes, {})
    return blocks


def effective_child_directives(
    block: BlockNode,
    directive_name: str,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> list[DirectiveNode]:
    server_directives = find_child_directives(block, directive_name)
    if server_directives:
        return server_directives
    return inherited_directives.get(directive_name, [])


def last_directive_is_on(directives: list[DirectiveNode]) -> bool:
    if not directives:
        return False
    last = directives[-1]
    return len(last.args) == 1 and last.args[0].lower() == "on"


__all__ = [
    "effective_child_directives",
    "iter_blocks_with_inherited_directives",
    "iter_server_blocks_with_http_directives",
    "iter_direct_child_directives",
    "iter_last_direct_child_directives",
    "last_directive_is_on",
    "parse_duration_seconds",
    "parse_size_bytes",
]
