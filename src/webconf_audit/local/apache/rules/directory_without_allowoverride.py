from __future__ import annotations

from dataclasses import dataclass
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
_SCOPE_BLOCK_NAMES = frozenset(
    {"virtualhost", "if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)


@dataclass(frozen=True, slots=True)
class _DirectoryBlockContext:
    block: ApacheBlockNode
    scope: tuple[int, ...]


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
    directory_contexts = _iter_directory_contexts(config_ast.nodes)

    for context in directory_contexts:
        block = context.block
        if not block.args:
            continue
        if _has_explicit_allowoverride(block):
            continue
        if _effective_allowoverride(context, directory_contexts) == frozenset():
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
    context: _DirectoryBlockContext,
    all_contexts: list[_DirectoryBlockContext],
) -> frozenset[str] | None:
    block_path = _resolve_block_path(context.block)
    if block_path is None:
        return None

    best_match: tuple[int, int, int, frozenset[str]] | None = None
    for source_order, candidate_context in enumerate(all_contexts):
        if not _scope_can_inherit(
            target_scope=context.scope,
            candidate_scope=candidate_context.scope,
        ):
            continue

        candidate_path = _resolve_block_path(candidate_context.block)
        if candidate_path is None:
            continue

        allowed = extract_allowoverride(candidate_context.block)
        if allowed is None:
            continue

        if not directory_path_covers(block_path, candidate_path):
            continue

        specificity = path_match_specificity(candidate_path)
        scope_depth = len(candidate_context.scope)
        if (
            best_match is None
            or specificity > best_match[0]
            or (specificity == best_match[0] and scope_depth > best_match[1])
            or (
                specificity == best_match[0]
                and scope_depth == best_match[1]
                and source_order > best_match[2]
            )
        ):
            best_match = (specificity, scope_depth, source_order, allowed)

    return best_match[3] if best_match is not None else None


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


def _scope_can_inherit(
    *,
    target_scope: tuple[int, ...],
    candidate_scope: tuple[int, ...],
) -> bool:
    return (
        len(candidate_scope) <= len(target_scope)
        and target_scope[: len(candidate_scope)] == candidate_scope
    )


def _iter_directory_contexts(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    scope: tuple[int, ...] = (),
) -> list[_DirectoryBlockContext]:
    blocks: list[_DirectoryBlockContext] = []
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            name = node.name.lower()
            if name == "directory":
                blocks.append(_DirectoryBlockContext(block=node, scope=scope))
                continue

            next_scope = scope
            if name in _SCOPE_BLOCK_NAMES:
                next_scope = (*scope, id(node))
            blocks.extend(_iter_directory_contexts(node.children, next_scope))
    return blocks


__all__ = ["find_directory_without_allowoverride"]
