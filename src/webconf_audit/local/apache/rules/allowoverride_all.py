"""apache.allowoverride_all_in_directory -- Directory block leaves AllowOverride too broad."""

from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache.htaccess import (
    ALL_OVERRIDE_CATEGORIES,
    extract_allowoverride,
)
from webconf_audit.local.apache.path_matching import (
    directory_path_covers,
    path_match_specificity,
)
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.allowoverride_all_in_directory"


@rule(
    rule_id=RULE_ID,
    title="Directory block leaves AllowOverride too broad",
    severity="medium",
    description=(
        "Directory block explicitly or effectively leaves AllowOverride at "
        "'All' or unspecified, which can let .htaccess override more "
        "directives than intended."
    ),
    recommendation=(
        "Set 'AllowOverride None' or restrict to specific categories to limit "
        "what .htaccess files can override."
    ),
    category="local",
    server_type="apache",
    order=300,
)
def find_allowoverride_all(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    directory_blocks = _iter_directory_blocks(config_ast.nodes)

    for block in directory_blocks:
        # Apache merges <Directory> declarations at the same resolved path
        # last-wins; the rule must reflect that effective scope rather than
        # this block's own AllowOverride directive in isolation.
        winner = _same_path_allowoverride_winner(block, directory_blocks)
        direct_allowed = extract_allowoverride(winner) if winner is not None else None
        effective_allowed = _find_effective_allowoverride(block, directory_blocks)

        if direct_allowed == ALL_OVERRIDE_CATEGORIES:
            # Emit on the block whose AllowOverride directive actually wins
            # the same-path merge so repeated declarations collapse to one
            # finding pointed at the directive that matters.
            if winner is block:
                findings.append(
                    _make_finding(
                        block,
                        description=(
                            "'AllowOverride All' allows .htaccess files to "
                            "override any directive in this Directory scope. "
                            "This weakens centralized configuration control."
                        ),
                    )
                )
            continue

        # A restrictive AllowOverride won the same-path merge — no finding.
        if direct_allowed is not None:
            continue

        # No same-path declaration sets AllowOverride. Emit case 2/3 only on
        # the earliest block at this path so repeated silent declarations
        # do not produce duplicate findings.
        if not _is_first_at_same_path(block, directory_blocks):
            continue

        if effective_allowed is None:
            findings.append(
                _make_finding(
                    block,
                    description=(
                        "No AllowOverride directive is set in this Directory "
                        "block or any covering parent Directory block. "
                        "Depending on the Apache version and global defaults, "
                        ".htaccess files may be able to override any directive."
                    ),
                )
            )
            continue

        if effective_allowed == ALL_OVERRIDE_CATEGORIES:
            findings.append(
                _make_finding(
                    block,
                    description=(
                        "This Directory block does not set AllowOverride, but "
                        "an inherited parent Directory scope effectively leaves "
                        "it at 'All'. That allows .htaccess files to override "
                        "any directive here."
                    ),
                )
            )

    return findings


def _make_finding(block: ApacheBlockNode, *, description: str) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Directory block leaves AllowOverride too broad",
        severity="medium",
        description=description,
        recommendation=(
            "Set 'AllowOverride None' or restrict to specific "
            "categories (e.g., 'AllowOverride FileInfo AuthConfig') "
            "to limit what .htaccess can override."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=block.source.file_path,
            line=block.source.line,
        ),
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


def _same_path_allowoverride_winner(
    block: ApacheBlockNode,
    all_blocks: list[ApacheBlockNode],
) -> ApacheBlockNode | None:
    block_path = _resolve_block_path(block)
    if block_path is None:
        return block if extract_allowoverride(block) is not None else None

    winner: ApacheBlockNode | None = None
    for candidate in all_blocks:
        candidate_path = _resolve_block_path(candidate)
        if candidate_path != block_path:
            continue
        if extract_allowoverride(candidate) is None:
            continue
        winner = candidate

    return winner


def _is_first_at_same_path(
    block: ApacheBlockNode,
    all_blocks: list[ApacheBlockNode],
) -> bool:
    block_path = _resolve_block_path(block)
    if block_path is None:
        return True

    for candidate in all_blocks:
        if candidate is block:
            return True
        if _resolve_block_path(candidate) == block_path:
            return False

    return True


def _find_effective_allowoverride(
    block: ApacheBlockNode,
    all_blocks: list[ApacheBlockNode],
) -> frozenset[str] | None:
    block_path = _resolve_block_path(block)
    if block_path is None:
        return None

    best_match: tuple[int, frozenset[str]] | None = None
    for candidate in all_blocks:
        if candidate is block:
            continue

        candidate_path = _resolve_block_path(candidate)
        if candidate_path is None:
            continue

        # Inherited override only: a peer block declared at the same
        # resolved path is the same Apache scope (last-wins merge), not a
        # covering parent. Skip both self and same-path peers so a block's
        # own scope cannot mask a real covering parent.
        if candidate_path == block_path:
            continue

        allowed = extract_allowoverride(candidate)
        if allowed is None:
            continue

        if not directory_path_covers(block_path, candidate_path):
            continue

        specificity = path_match_specificity(candidate_path)
        if best_match is None or specificity >= best_match[0]:
            best_match = (specificity, allowed)

    return best_match[1] if best_match is not None else None


def _resolve_block_path(block: ApacheBlockNode) -> Path | None:
    if not block.args:
        return None

    raw_path = Path(block.args[0])
    if raw_path.is_absolute():
        return raw_path.resolve()

    source_file_path = block.source.file_path
    if source_file_path is None:
        return raw_path.resolve()

    return (Path(source_file_path).parent / raw_path).resolve()


__all__ = ["find_allowoverride_all"]
