"""Shared helpers for exact Apache ``<Directory />`` root-scope handling."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheDirectiveNode


@dataclass(frozen=True, slots=True)
class DirectoryBlockOccurrence:
    block: ApacheBlockNode
    virtualhost: ApacheBlockNode | None
    order: int


def collect_directory_block_occurrences(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[DirectoryBlockOccurrence]:
    occurrences: list[DirectoryBlockOccurrence] = []
    _collect_directory_block_occurrences(
        nodes,
        occurrences=occurrences,
        source_virtualhost_block=None,
    )
    return occurrences


def directory_key(block: ApacheBlockNode) -> Path | str | None:
    if not block.args:
        return None

    raw_path = block.args[0]
    if raw_path.startswith("~"):
        return None
    if raw_path == "/":
        return Path("/")

    path = Path(raw_path)
    if path.is_absolute():
        return path.resolve()

    source_file_path = block.source.file_path
    if source_file_path is None:
        return path.resolve()

    return (Path(source_file_path).parent / path).resolve()


def group_directory_blocks_by_path(
    directory_blocks: list[ApacheBlockNode],
) -> dict[Path | str, list[ApacheBlockNode]]:
    groups: dict[Path | str, list[ApacheBlockNode]] = {}
    for block in directory_blocks:
        key = directory_key(block)
        if key is None:
            continue
        groups.setdefault(key, []).append(block)
    return groups


def is_os_root_directory_block(block: ApacheBlockNode) -> bool:
    return bool(block.args) and block.args[0] == "/"


def is_os_root_directory_group(blocks: list[ApacheBlockNode]) -> bool:
    return any(is_os_root_directory_block(block) for block in blocks)


def _collect_directory_block_occurrences(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    occurrences: list[DirectoryBlockOccurrence],
    source_virtualhost_block: ApacheBlockNode | None,
) -> None:
    for node in nodes:
        if not isinstance(node, ApacheBlockNode):
            continue

        current_virtualhost = (
            node if node.name.lower() == "virtualhost" else source_virtualhost_block
        )
        if node.name.lower() == "directory":
            occurrences.append(
                DirectoryBlockOccurrence(
                    block=node,
                    virtualhost=source_virtualhost_block,
                    order=len(occurrences),
                )
            )

        _collect_directory_block_occurrences(
            node.children,
            occurrences=occurrences,
            source_virtualhost_block=current_virtualhost,
        )


__all__ = [
    "DirectoryBlockOccurrence",
    "collect_directory_block_occurrences",
    "directory_key",
    "group_directory_blocks_by_path",
    "is_os_root_directory_block",
    "is_os_root_directory_group",
]
