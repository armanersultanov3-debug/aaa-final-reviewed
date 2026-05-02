from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._block_policy_utils import default_location, iter_blocks
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.allowoverride_not_none"


@rule(
    rule_id=RULE_ID,
    title="Directory scope allows .htaccess overrides",
    severity="medium",
    description=(
        "A Directory scope does not enforce 'AllowOverride None', leaving "
        ".htaccess override behavior enabled or ambiguous for CIS hardening."
    ),
    recommendation=(
        "Set 'AllowOverride None' in the OS-root Directory scope and avoid "
        "enabling .htaccess overrides in application Directory scopes."
    ),
    category="local",
    server_type="apache",
    order=341,
)
def find_allowoverride_not_none(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    directory_blocks = list(iter_blocks(config_ast.nodes, frozenset({"directory"})))
    winners = _winning_directory_blocks_by_path(directory_blocks)

    if not any(_is_os_root_directory(block) for block in winners.values()):
        findings.append(_make_missing_root_finding(config_ast))

    for block in winners.values():
        directive = _find_allowoverride_directive(block)
        if directive is not None and _is_allowoverride_none(directive):
            continue

        if directive is None and not _is_os_root_directory(block):
            continue

        findings.append(_make_finding(block, directive=directive))

    return findings


def _make_missing_root_finding(config_ast: ApacheConfigAst) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Directory scope allows .htaccess overrides",
        severity="medium",
        description=(
            "Apache config does not define an OS-root '<Directory />' scope "
            "with 'AllowOverride None'. CIS Apache hardening expects this "
            "baseline before more specific Directory scopes."
        ),
        recommendation=(
            "Add '<Directory />' with 'AllowOverride None' near the global "
            "Directory baseline."
        ),
        location=default_location(config_ast),
    )


def _make_finding(
    block: ApacheBlockNode,
    *,
    directive: ApacheDirectiveNode | None,
) -> Finding:
    if directive is None:
        detail = "does not set 'AllowOverride None'"
    else:
        configured = " ".join(directive.args) if directive.args else "<missing value>"
        detail = f"sets 'AllowOverride {configured}'"

    return Finding(
        rule_id=RULE_ID,
        title="Directory scope allows .htaccess overrides",
        severity="medium",
        description=(
            f"This Directory scope {detail}; CIS Apache hardening expects "
            "'AllowOverride None' for centrally managed configuration."
        ),
        recommendation=(
            "Set this Directory scope to 'AllowOverride None' and move "
            "required overrides into the main Apache configuration."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=block.source.file_path,
            line=block.source.line,
        ),
    )


def _winning_directory_blocks_by_path(
    directory_blocks: list[ApacheBlockNode],
) -> dict[Path | str, ApacheBlockNode]:
    winners: dict[Path | str, ApacheBlockNode] = {}
    for block in directory_blocks:
        key = _directory_key(block)
        if key is None:
            continue
        winners[key] = block
    return winners


def _directory_key(block: ApacheBlockNode) -> Path | str | None:
    if not block.args:
        return None

    raw_path = block.args[0]
    if raw_path == "/":
        return Path("/")

    path = Path(raw_path)
    if path.is_absolute():
        return path.resolve()

    source_file_path = block.source.file_path
    if source_file_path is None:
        return path.resolve()

    return (Path(source_file_path).parent / path).resolve()


def _is_os_root_directory(block: ApacheBlockNode) -> bool:
    return bool(block.args and block.args[0] == "/")


def _is_allowoverride_none(directive: ApacheDirectiveNode) -> bool:
    return len(directive.args) == 1 and directive.args[0].lower() == "none"


def _find_allowoverride_directive(block: ApacheBlockNode) -> ApacheDirectiveNode | None:
    winner: ApacheDirectiveNode | None = None
    for child in block.children:
        if (
            isinstance(child, ApacheDirectiveNode)
            and child.name.lower() == "allowoverride"
        ):
            winner = child
    return winner


__all__ = ["find_allowoverride_not_none"]
