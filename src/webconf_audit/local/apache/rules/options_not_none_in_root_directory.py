"""apache.options_not_none_in_root_directory -- OS-root Directory scope does not enforce Options None."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from webconf_audit.local.apache.effective import APACHE_ALL_OPTIONS
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._block_policy_utils import default_location, iter_blocks
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.options_not_none_in_root_directory"
_TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)


@dataclass(frozen=True, slots=True)
class _MergedOptionsState:
    tokens: list[str]
    baseline_proven: bool


@dataclass(frozen=True, slots=True)
class _EvaluatedOptionsDirective:
    directive: ApacheDirectiveNode
    baseline_proven: bool


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
        global_options = _effective_global_options_state(config_ast)
        if global_options is not None and _is_empty_options_baseline(global_options):
            return []
        return [_make_missing_root_finding(config_ast)]

    for blocks in root_blocks:
        evaluated = _effective_options_directive(blocks)
        if evaluated is not None and _is_effective_options_none(evaluated):
            continue
        findings.append(_make_finding(blocks[-1], evaluated=evaluated))

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
    evaluated: _EvaluatedOptionsDirective | None,
) -> Finding:
    directive = evaluated.directive if evaluated is not None else None
    if directive is None:
        detail = "does not set an effective empty 'Options' baseline"
    elif not evaluated.baseline_proven and not directive.args:
        detail = (
            "uses subtractive-only 'Options' modifiers without proving an "
            "empty baseline"
        )
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


def _iter_options_directives(block: ApacheBlockNode) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for child in block.children:
        if isinstance(child, ApacheDirectiveNode):
            if child.name.lower() == "options":
                directives.append(child)
            continue
        if child.name.lower() in _TRANSPARENT_WRAPPER_BLOCKS:
            directives.extend(_iter_options_directives(child))
    return directives


def _effective_options_directive(
    blocks: list[ApacheBlockNode],
) -> _EvaluatedOptionsDirective | None:
    state: _MergedOptionsState | None = None
    effective_directive: ApacheDirectiveNode | None = None

    for block in blocks:
        for directive in _iter_options_directives(block):
            state = _merge_options_tokens(state, directive.args)
            effective_directive = ApacheDirectiveNode(
                name=directive.name,
                args=list(state.tokens),
                source=directive.source,
            )

    if effective_directive is None or state is None:
        return None

    return _EvaluatedOptionsDirective(
        directive=effective_directive,
        baseline_proven=state.baseline_proven,
    )


def _effective_global_options_state(
    config_ast: ApacheConfigAst,
) -> _MergedOptionsState | None:
    state: _MergedOptionsState | None = None
    for directive in _iter_top_level_directives(config_ast.nodes):
        if directive.name.lower() != "options":
            continue
        state = _merge_options_tokens(state, directive.args)
    return state


def _merge_options_tokens(
    current_state: _MergedOptionsState | None,
    directive_args: list[str],
) -> _MergedOptionsState:
    current_set = set(current_state.tokens if current_state is not None else [])
    baseline_proven = (
        current_state.baseline_proven if current_state is not None else False
    )
    absolute_group_active = False

    for arg in directive_args:
        lowered = arg.lower()
        if lowered == "none":
            current_set.clear()
            absolute_group_active = True
            baseline_proven = True
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
            baseline_proven = True

    return _MergedOptionsState(
        tokens=sorted(current_set),
        baseline_proven=baseline_proven,
    )


def _is_effective_options_none(
    evaluated: _EvaluatedOptionsDirective,
) -> bool:
    return (
        evaluated.baseline_proven
        and _is_effective_options_none_args(evaluated.directive.args)
    )


def _is_effective_options_none_args(args: list[str]) -> bool:
    return len(args) == 0


def _is_empty_options_baseline(state: _MergedOptionsState) -> bool:
    return state.baseline_proven and _is_effective_options_none_args(state.tokens)


def _iter_top_level_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
        elif node.name.lower() in _TRANSPARENT_WRAPPER_BLOCKS:
            directives.extend(_iter_top_level_directives(node.children))
    return directives


def _expanded_option_token(token: str) -> frozenset[str]:
    if token == "all":
        return APACHE_ALL_OPTIONS
    if token == "none":
        return frozenset()
    return frozenset({token})


__all__ = ["find_options_not_none_in_root_directory"]
