from __future__ import annotations

from collections.abc import Iterable

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.models import SourceLocation

TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)


def iter_blocks(
    nodes: Iterable[ApacheDirectiveNode | ApacheBlockNode],
    names: frozenset[str],
) -> Iterable[ApacheBlockNode]:
    for node in nodes:
        if not isinstance(node, ApacheBlockNode):
            continue
        if node.name.lower() in names:
            yield node
        yield from iter_blocks(node.children, names)


def iter_directives(
    nodes: Iterable[ApacheDirectiveNode | ApacheBlockNode],
    name: str,
) -> Iterable[ApacheDirectiveNode]:
    normalized_name = name.lower()
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if node.name.lower() == normalized_name:
                yield node
            continue

        yield from iter_directives(node.children, normalized_name)


def block_denies_all(block: ApacheBlockNode) -> bool:
    for child in block.children:
        if isinstance(child, ApacheDirectiveNode):
            if _directive_denies_all(child):
                return True
            continue

        if child.name.lower() in TRANSPARENT_WRAPPER_BLOCKS and block_denies_all(child):
            return True

    return False


def denied_extensions(
    config_ast: ApacheConfigAst,
    *,
    extensions: tuple[str, ...],
    block_names: frozenset[str],
) -> set[str]:
    covered: set[str] = set()
    for block in iter_blocks(config_ast.nodes, block_names):
        if not block_denies_all(block):
            continue

        pattern = block_pattern_text(block)
        covered.update(
            extension
            for extension in extensions
            if pattern_mentions_extension(pattern, extension)
        )

    return covered


def has_denied_pattern(
    config_ast: ApacheConfigAst,
    *,
    markers: tuple[str, ...],
    block_names: frozenset[str],
) -> bool:
    normalized_markers = tuple(marker.lower() for marker in markers)
    for block in iter_blocks(config_ast.nodes, block_names):
        if not block_denies_all(block):
            continue
        pattern = block_pattern_text(block)
        if any(marker in pattern for marker in normalized_markers):
            return True

    return False


def block_pattern_text(block: ApacheBlockNode) -> str:
    return " ".join(block.args).lower()


def pattern_mentions_extension(pattern: str, extension: str) -> bool:
    explicit_markers = (
        f"\\.{extension}",
        f".{extension}",
        f"({extension}",
        f"|{extension}",
        f"{extension}|",
        f"{extension})",
    )
    return any(marker in pattern for marker in explicit_markers)


def default_location(
    config_ast: ApacheConfigAst,
    candidate_blocks: list[ApacheBlockNode] | None = None,
) -> SourceLocation | None:
    if candidate_blocks:
        source = candidate_blocks[0].source
        return SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        )

    if not config_ast.nodes:
        return None

    source = config_ast.nodes[0].source
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=source.file_path,
        line=source.line,
    )


def _directive_denies_all(directive: ApacheDirectiveNode) -> bool:
    name = directive.name.lower()
    args = [arg.lower() for arg in directive.args]

    if name == "require" and args == ["all", "denied"]:
        return True
    if name == "deny" and args == ["from", "all"]:
        return True

    return False


__all__ = [
    "block_denies_all",
    "block_pattern_text",
    "default_location",
    "denied_extensions",
    "has_denied_pattern",
    "iter_blocks",
    "iter_directives",
    "pattern_mentions_extension",
]
