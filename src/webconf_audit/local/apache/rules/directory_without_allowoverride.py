from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache.htaccess import extract_allowoverride
from webconf_audit.local.apache.path_matching import (
    directory_path_covers,
    path_match_specificity,
)
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.directory_without_allowoverride"


@rule(
    rule_id=RULE_ID,
    title="Directory block lacks explicit AllowOverride",
    severity="low",
    description=(
        "This Directory block does not set AllowOverride explicitly. That "
        "makes .htaccess behavior depend on inherited or default Apache "
        "settings, which is harder to audit."
    ),
    recommendation=(
        "Set AllowOverride explicitly for each Directory block, preferably "
        "'AllowOverride None' or a narrow category list."
    ),
    category="local",
    server_type="apache",
    order=303,
)
def find_directory_without_allowoverride(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    directory_blocks = _iter_directory_blocks(config_ast.nodes)

    for block in directory_blocks:
        if not block.args:
            continue
        if _has_explicit_allowoverride(block):
            continue
        if _effective_allowoverride(block, directory_blocks) == frozenset():
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Directory block lacks explicit AllowOverride",
                severity="low",
                description=(
                    "This Directory block does not set AllowOverride explicitly. "
                    "That makes .htaccess behavior depend on inherited or default "
                    "Apache settings, which is harder to audit."
                ),
                recommendation=(
                    "Set AllowOverride explicitly for each Directory block, "
                    "preferably 'AllowOverride None' or a narrow category list."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=block.source.file_path,
                    line=block.source.line,
                ),
            )
        )

    return findings


def _effective_allowoverride(
    block: ApacheBlockNode,
    all_blocks: list[ApacheBlockNode],
) -> frozenset[str] | None:
    block_path = _resolve_block_path(block)
    if block_path is None:
        return None

    best_match: tuple[int, int, frozenset[str]] | None = None
    for source_order, candidate in enumerate(all_blocks):
        candidate_path = _resolve_block_path(candidate)
        if candidate_path is None:
            continue

        allowed = extract_allowoverride(candidate)
        if allowed is None:
            continue

        if not directory_path_covers(block_path, candidate_path):
            continue

        specificity = path_match_specificity(candidate_path)
        if (
            best_match is None
            or specificity > best_match[0]
            or (specificity == best_match[0] and source_order > best_match[1])
        ):
            best_match = (specificity, source_order, allowed)

    return best_match[2] if best_match is not None else None


def _resolve_block_path(block: ApacheBlockNode) -> Path | None:
    if not block.args:
        return None

    raw_path = Path(block.args[0])
    if raw_path.is_absolute():
        return raw_path

    source_file_path = block.source.file_path
    if source_file_path is None:
        return raw_path

    return Path(source_file_path).parent / raw_path


def _has_explicit_allowoverride(block: ApacheBlockNode) -> bool:
    return any(
        isinstance(child, ApacheDirectiveNode) and child.name.lower() == "allowoverride"
        for child in block.children
    )


def _iter_directory_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheBlockNode]:
    blocks: list[ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() == "directory":
                blocks.append(node)
            blocks.extend(_iter_directory_blocks(node.children))
    return blocks


__all__ = ["find_directory_without_allowoverride"]
