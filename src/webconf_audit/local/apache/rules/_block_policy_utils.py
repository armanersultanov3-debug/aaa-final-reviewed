"""Internal helpers for the block policy utils rule family.

Location: ``src/webconf_audit/local/apache/rules/_block_policy_utils.py``.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import re

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    extract_document_root,
    iter_directory_blocks_for_context,
)
from webconf_audit.local.apache.path_matching import directory_path_covers
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.models import SourceLocation

TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)
LOCATION_BLOCKS = frozenset({"location", "locationmatch"})


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
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> set[str]:
    covered: set[str] = set()
    for block in iter_policy_blocks(
        config_ast,
        block_names,
        virtualhost_context=virtualhost_context,
    ):
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
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> bool:
    normalized_markers = tuple(marker.lower() for marker in markers)
    for block in iter_policy_blocks(
        config_ast,
        block_names,
        virtualhost_context=virtualhost_context,
    ):
        if not block_denies_all(block):
            continue
        pattern = block_pattern_text(block)
        if any(_contains_pattern_segment(pattern, marker) for marker in normalized_markers):
            return True

    return False


def denied_pattern_text(
    config_ast: ApacheConfigAst,
    *,
    block_names: frozenset[str],
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> str:
    return " ".join(
        block_pattern_text(block)
        for block in iter_policy_blocks(
            config_ast,
            block_names,
            virtualhost_context=virtualhost_context,
        )
        if block_denies_all(block)
    )


def iter_policy_blocks(
    config_ast: ApacheConfigAst,
    block_names: frozenset[str],
    *,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> Iterable[ApacheBlockNode]:
    if virtualhost_context is None:
        yield from iter_blocks(config_ast.nodes, block_names)
        return

    yield from _iter_server_or_virtualhost_policy_blocks(
        config_ast.nodes,
        block_names,
        virtualhost_context=virtualhost_context,
    )
    yield from _iter_document_root_directory_policy_blocks(
        config_ast,
        block_names,
        virtualhost_context=virtualhost_context,
    )


def block_pattern_text(block: ApacheBlockNode) -> str:
    return " ".join(block.args).lower()


def pattern_mentions_extension(pattern: str, extension: str) -> bool:
    escaped_extension = re.escape(extension.lower())
    return (
        re.search(
            rf"(?<![a-z0-9_])\\?\.{escaped_extension}(?![a-z0-9_])",
            pattern,
        )
        is not None
        or re.search(rf"(?<=[(|]){escaped_extension}(?=[|)])", pattern)
        is not None
    )


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


def _iter_server_or_virtualhost_policy_blocks(
    nodes: Iterable[ApacheDirectiveNode | ApacheBlockNode],
    block_names: frozenset[str],
    *,
    virtualhost_context: ApacheVirtualHostContext,
) -> Iterable[ApacheBlockNode]:
    for node in nodes:
        if not isinstance(node, ApacheBlockNode):
            continue

        name = node.name.lower()
        if name == "virtualhost":
            if node is virtualhost_context.node:
                yield from _iter_server_or_virtualhost_policy_blocks(
                    node.children,
                    block_names,
                    virtualhost_context=virtualhost_context,
                )
            continue

        if name in LOCATION_BLOCKS:
            if name in block_names:
                yield node
            continue

        if name == "directory":
            continue

        if name in block_names:
            yield node

        if name in TRANSPARENT_WRAPPER_BLOCKS:
            yield from _iter_server_or_virtualhost_policy_blocks(
                node.children,
                block_names,
                virtualhost_context=virtualhost_context,
            )


def _iter_document_root_directory_policy_blocks(
    config_ast: ApacheConfigAst,
    block_names: frozenset[str],
    *,
    virtualhost_context: ApacheVirtualHostContext,
) -> Iterable[ApacheBlockNode]:
    document_root = extract_document_root(
        config_ast,
        virtualhost_context=virtualhost_context,
    )
    if document_root is None:
        return

    for directory_block, _source_priority in iter_directory_blocks_for_context(
        config_ast,
        virtualhost_context=virtualhost_context,
    ):
        if not _directory_covers_document_root(directory_block, document_root):
            continue

        if "directory" in block_names:
            yield directory_block

        yield from _iter_directory_child_policy_blocks(
            directory_block.children,
            block_names,
        )


def _iter_directory_child_policy_blocks(
    nodes: Iterable[ApacheDirectiveNode | ApacheBlockNode],
    block_names: frozenset[str],
) -> Iterable[ApacheBlockNode]:
    for node in nodes:
        if not isinstance(node, ApacheBlockNode):
            continue

        name = node.name.lower()
        if name in LOCATION_BLOCKS or name == "directory":
            continue

        if name in block_names:
            yield node

        if name in TRANSPARENT_WRAPPER_BLOCKS:
            yield from _iter_directory_child_policy_blocks(
                node.children,
                block_names,
            )


def _directory_covers_document_root(
    directory_block: ApacheBlockNode,
    document_root: Path,
) -> bool:
    if not directory_block.args:
        return False

    raw_path = directory_block.args[0]
    if raw_path.startswith("~"):
        return False

    directory_path = Path(raw_path)
    if not directory_path.is_absolute() and directory_block.source.file_path:
        directory_path = Path(directory_block.source.file_path).parent / directory_path

    return directory_path_covers(
        document_root,
        directory_path,
        resolve=True,
        case_sensitive=False,
    )


def _contains_pattern_segment(pattern: str, marker: str) -> bool:
    return (
        re.search(
            rf"(?<![a-z0-9_]){re.escape(marker)}(?![a-z0-9_])",
            pattern,
        )
        is not None
    )


__all__ = [
    "block_denies_all",
    "block_pattern_text",
    "default_location",
    "denied_pattern_text",
    "denied_extensions",
    "has_denied_pattern",
    "iter_blocks",
    "iter_policy_blocks",
    "iter_directives",
    "pattern_mentions_extension",
]
