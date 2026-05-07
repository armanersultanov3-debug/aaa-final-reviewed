from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache.effective import (
    APACHE_ALL_OPTIONS,
    build_server_effective_config,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._block_policy_utils import default_location, iter_blocks
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.options_not_none_in_root_directory"


@rule(
    rule_id=RULE_ID,
    title="OS-root Directory scope does not enforce Options None",
    severity="medium",
    description=(
        "Apache config does not enforce an empty 'Options' baseline for the "
        "OS-root '<Directory />' scope. CIS hardening expects 'Options None' "
        "there before narrower Directory scopes re-enable only what they need."
    ),
    recommendation=(
        "Set 'Options None' in the OS-root '<Directory />' scope and re-enable "
        "required options only in narrower Directory scopes."
    ),
    category="local",
    server_type="apache",
    order=319,
)
def find_options_not_none_in_root_directory(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    directory_blocks = list(iter_blocks(config_ast.nodes, frozenset({"directory"})))
    groups = _group_directory_blocks_by_path(directory_blocks)

    root_blocks = [blocks for blocks in groups.values() if _is_os_root_directory(blocks)]
    if not root_blocks:
        global_options = build_server_effective_config(config_ast).directives.get("options")
        if global_options is not None and _is_effective_options_none_args(global_options.args):
            return []
        return [_make_missing_root_finding(config_ast)]

    for blocks in root_blocks:
        directive = _effective_options_directive(blocks)
        if directive is not None and _is_effective_options_none(directive):
            continue
        findings.append(_make_finding(blocks[-1], directive=directive))

    return findings


def _make_missing_root_finding(config_ast: ApacheConfigAst) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="OS-root Directory scope does not enforce Options None",
        severity="medium",
        description=(
            "Apache config does not define an OS-root '<Directory />' scope "
            "with 'Options None'. CIS hardening expects this baseline before "
            "more specific Directory scopes."
        ),
        recommendation=(
            "Add '<Directory />' with 'Options None' near the global Directory "
            "baseline."
        ),
        location=default_location(config_ast),
    )


def _make_finding(
    block: ApacheBlockNode,
    *,
    directive: ApacheDirectiveNode | None,
) -> Finding:
    if directive is None:
        detail = "does not set an effective empty 'Options' baseline"
    else:
        configured = " ".join(directive.args) if directive.args else "<empty>"
        detail = f"sets effective 'Options {configured}'"

    return Finding(
        rule_id=RULE_ID,
        title="OS-root Directory scope does not enforce Options None",
        severity="medium",
        description=(
            f"This OS-root Directory scope {detail}; CIS hardening expects "
            "'Options None' before narrower Directory scopes selectively "
            "re-enable required options."
        ),
        recommendation=(
            "Set this OS-root Directory scope to 'Options None' and move "
            "required options into narrower Directory scopes."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=(
                directive.source if directive is not None else block.source
            ).file_path,
            line=(directive.source if directive is not None else block.source).line,
        ),
    )


def _group_directory_blocks_by_path(
    directory_blocks: list[ApacheBlockNode],
) -> dict[Path | str, list[ApacheBlockNode]]:
    groups: dict[Path | str, list[ApacheBlockNode]] = {}
    for block in directory_blocks:
        key = _directory_key(block)
        if key is None:
            continue
        groups.setdefault(key, []).append(block)
    return groups


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


def _is_os_root_directory(blocks: list[ApacheBlockNode]) -> bool:
    return any(block.args and block.args[0] == "/" for block in blocks)


def _find_options_directive(block: ApacheBlockNode) -> ApacheDirectiveNode | None:
    winner: ApacheDirectiveNode | None = None
    for child in block.children:
        if isinstance(child, ApacheDirectiveNode) and child.name.lower() == "options":
            winner = child
    return winner


def _effective_options_directive(
    blocks: list[ApacheBlockNode],
) -> ApacheDirectiveNode | None:
    effective_tokens: list[str] | None = None
    effective_directive: ApacheDirectiveNode | None = None

    for block in blocks:
        directive = _find_options_directive(block)
        if directive is None:
            continue
        effective_tokens = _merge_options_tokens(effective_tokens, directive.args)
        effective_directive = ApacheDirectiveNode(
            name=directive.name,
            args=effective_tokens,
            source=directive.source,
        )

    return effective_directive


def _merge_options_tokens(
    current_tokens: list[str] | None,
    directive_args: list[str],
) -> list[str]:
    current_set = set(current_tokens or [])
    absolute_group_active = False

    for arg in directive_args:
        lowered = arg.lower()
        if lowered == "none":
            current_set.clear()
            absolute_group_active = True
        elif arg.startswith("+"):
            current_set.update(_expanded_option_token(arg[1:].lower()))
            absolute_group_active = False
        elif arg.startswith("-"):
            current_set.difference_update(_expanded_option_token(arg[1:].lower()))
            absolute_group_active = False
        else:
            if not absolute_group_active:
                current_set.clear()
                absolute_group_active = True
            current_set.update(_expanded_option_token(lowered))

    return sorted(current_set)


def _is_effective_options_none(directive: ApacheDirectiveNode) -> bool:
    return _is_effective_options_none_args(directive.args)


def _is_effective_options_none_args(args: list[str] | list[list[str]]) -> bool:
    return len(args) == 0


def _expanded_option_token(token: str) -> frozenset[str]:
    if token == "all":
        return APACHE_ALL_OPTIONS
    if token == "none":
        return frozenset()
    return frozenset({token})


__all__ = ["find_options_not_none_in_root_directory"]
