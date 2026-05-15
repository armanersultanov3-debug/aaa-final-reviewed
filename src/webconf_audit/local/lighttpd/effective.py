"""Lighttpd effective-configuration computation.

Combines global directives with ``$HTTP[...]`` / ``$SERVER[...]``
conditional scopes to produce an effective view per request context.
Rules consume :class:`LighttpdEffectiveConfig` plus merged directive
maps (per-host or no-host) so the same checker code can answer both
targeted ``--host`` queries and global "any branch" questions.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from webconf_audit.local.lighttpd.conditions import is_potentially_matching
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdCondition,
    LighttpdConfigAst,
    LighttpdSourceSpan,
)

if TYPE_CHECKING:
    from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext


@dataclass(frozen=True, slots=True)
class LighttpdEffectiveDirective:
    name: str
    value: str
    operator: str
    scope: str  # "global" or "conditional"
    condition: LighttpdCondition | None
    source: LighttpdSourceSpan
    conditions: tuple[LighttpdCondition | None, ...] = ()
    branch_path: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class LighttpdConditionalScope:
    condition: LighttpdCondition | None
    header: str
    directives: dict[str, LighttpdEffectiveDirective]
    # Full chain of ancestor conditions (outermost first).
    # For a top-level block this equals ``(condition,)`` when condition is set.
    # For a nested block it contains the parent's conditions followed by this one.
    conditions: tuple[LighttpdCondition | None, ...] = ()
    # True when this scope is an ``else`` block.
    is_else: bool = False
    # True when this scope is an ``else if``/``elseif``/``elsif`` branch.
    is_else_if: bool = False
    # Index of the sibling if-scope that this else belongs to (within
    # conditional_scopes list).  -1 when not an else block.
    sibling_if_index: int = -1
    # All previous branches in the same if/elseif/else chain.
    previous_branch_indices: tuple[int, ...] = ()
    # One entry per nested if/elseif/else branch: (chain id, branch ordinal).
    branch_path: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class LighttpdEffectiveConfig:
    global_directives: dict[str, LighttpdEffectiveDirective] = field(
        default_factory=dict,
    )
    conditional_scopes: list[LighttpdConditionalScope] = field(
        default_factory=list,
    )

    def get_global(self, name: str) -> LighttpdEffectiveDirective | None:
        return self.global_directives.get(name)


def build_effective_config(
    config_ast: LighttpdConfigAst,
) -> LighttpdEffectiveConfig:
    global_directives: dict[str, LighttpdEffectiveDirective] = {}
    conditional_scopes: list[LighttpdConditionalScope] = []
    branch_chain_counter = [0]

    _collect_nodes(
        config_ast.nodes,
        global_directives,
        conditional_scopes,
        branch_chain_counter,
    )

    return LighttpdEffectiveConfig(
        global_directives=global_directives,
        conditional_scopes=conditional_scopes,
    )


def _collect_nodes(
    nodes: list,
    global_directives: dict[str, LighttpdEffectiveDirective],
    conditional_scopes: list[LighttpdConditionalScope],
    branch_chain_counter: list[int],
) -> None:
    branch_chain: list[int] = []
    branch_chain_id: int | None = None
    for node in nodes:
        if isinstance(node, LighttpdBlockNode):
            previous_branch_indices = (
                tuple(branch_chain) if node.branch_kind in {"else", "else_if"} else ()
            )
            if node.branch_kind == "if" or branch_chain_id is None:
                branch_chain_id = _next_branch_chain_id(branch_chain_counter)
            branch_link = (branch_chain_id, len(previous_branch_indices))
            my_index = _collect_block(
                node,
                conditional_scopes,
                parent_conditions=(),
                parent_branch_path=(),
                branch_link=branch_link,
                previous_branch_indices=previous_branch_indices,
                branch_chain_counter=branch_chain_counter,
            )
            branch_chain = _next_branch_chain(branch_chain, node.branch_kind, my_index)
            if not branch_chain:
                branch_chain_id = None
        else:
            if isinstance(node, LighttpdAssignmentNode):
                _apply_assignment(
                    node,
                    global_directives,
                    scope="global",
                    condition=None,
                    conditions=(),
                    branch_path=(),
                )
            branch_chain = []
            branch_chain_id = None


def _collect_block(
    block: LighttpdBlockNode,
    conditional_scopes: list[LighttpdConditionalScope],
    *,
    parent_conditions: tuple[LighttpdCondition | None, ...],
    parent_branch_path: tuple[tuple[int, int], ...],
    branch_link: tuple[int, int],
    previous_branch_indices: tuple[int, ...],
    branch_chain_counter: list[int],
) -> int:
    """Create a scope for this block's direct assignments, then recurse for nested blocks.

    Returns the index of the scope that was just appended (used as
    ``sibling_if_index`` for a following ``else`` block).
    """
    conditions = (*parent_conditions, block.condition)
    branch_path = (*parent_branch_path, branch_link)
    is_else = block.branch_kind == "else"
    is_else_if = block.branch_kind == "else_if"
    my_index = len(conditional_scopes)
    current_directives: dict[str, LighttpdEffectiveDirective] | None = {}
    _append_conditional_scope(
        conditional_scopes,
        block=block,
        directives=current_directives,
        conditions=conditions,
        branch_path=branch_path,
        is_else=is_else,
        is_else_if=is_else_if,
        previous_branch_indices=previous_branch_indices,
    )

    # Collect nested blocks — they inherit this block's full condition chain.
    nested_branch_chain: list[int] = []
    nested_branch_chain_id: int | None = None
    for child in block.children:
        if isinstance(child, LighttpdBlockNode):
            nested_previous_branch_indices = (
                tuple(nested_branch_chain)
                if child.branch_kind in {"else", "else_if"}
                else ()
            )
            if child.branch_kind == "if" or nested_branch_chain_id is None:
                nested_branch_chain_id = _next_branch_chain_id(branch_chain_counter)
            nested_branch_link = (
                nested_branch_chain_id,
                len(nested_previous_branch_indices),
            )
            nested_index = _collect_block(
                child,
                conditional_scopes,
                parent_conditions=conditions,
                parent_branch_path=branch_path,
                branch_link=nested_branch_link,
                previous_branch_indices=nested_previous_branch_indices,
                branch_chain_counter=branch_chain_counter,
            )
            nested_branch_chain = _next_branch_chain(
                nested_branch_chain,
                child.branch_kind,
                nested_index,
            )
            if not nested_branch_chain:
                nested_branch_chain_id = None
            # End the current direct-scope segment after _collect_block();
            # _apply_assignment will create the next one if assignments follow.
            current_directives = None
        else:
            if isinstance(child, LighttpdAssignmentNode):
                if current_directives is None:
                    current_directives = {}
                    _append_conditional_scope(
                        conditional_scopes,
                        block=block,
                        directives=current_directives,
                        conditions=conditions,
                        branch_path=branch_path,
                        is_else=is_else,
                        is_else_if=is_else_if,
                        previous_branch_indices=previous_branch_indices,
                    )
                _apply_assignment(
                    child,
                    current_directives,
                    scope="conditional",
                    condition=block.condition,
                    conditions=conditions,
                    branch_path=branch_path,
                )
            nested_branch_chain = []
            nested_branch_chain_id = None

    return my_index


def _append_conditional_scope(
    conditional_scopes: list[LighttpdConditionalScope],
    *,
    block: LighttpdBlockNode,
    directives: dict[str, LighttpdEffectiveDirective],
    conditions: tuple[LighttpdCondition | None, ...],
    branch_path: tuple[tuple[int, int], ...],
    is_else: bool,
    is_else_if: bool,
    previous_branch_indices: tuple[int, ...],
) -> None:
    conditional_scopes.append(
        LighttpdConditionalScope(
            condition=block.condition,
            header=block.header,
            directives=directives,
            conditions=conditions,
            is_else=is_else,
            is_else_if=is_else_if,
            sibling_if_index=previous_branch_indices[-1]
            if (is_else or is_else_if) and previous_branch_indices
            else -1,
            previous_branch_indices=previous_branch_indices,
            branch_path=branch_path,
        )
    )


def _next_branch_chain_id(branch_chain_counter: list[int]) -> int:
    branch_chain_id = branch_chain_counter[0]
    branch_chain_counter[0] += 1
    return branch_chain_id


def _next_branch_chain(
    branch_chain: list[int],
    branch_kind: str,
    my_index: int,
) -> list[int]:
    if branch_kind == "if":
        return [my_index]
    if branch_kind == "else_if":
        return [*branch_chain, my_index]
    return []


def _apply_assignment(
    node: LighttpdAssignmentNode,
    directives: dict[str, LighttpdEffectiveDirective],
    *,
    scope: str,
    condition: LighttpdCondition | None,
    conditions: tuple[LighttpdCondition | None, ...],
    branch_path: tuple[tuple[int, int], ...],
) -> None:
    effective = LighttpdEffectiveDirective(
        name=node.name,
        value=node.value,
        operator=node.operator,
        scope=scope,
        condition=condition,
        source=node.source,
        conditions=conditions,
        branch_path=branch_path,
    )

    if node.operator == "+=" and node.name in directives:
        prev = directives[node.name]
        merged_value = _merge_append(prev.value, node.value)
        effective = LighttpdEffectiveDirective(
            name=node.name,
            value=merged_value,
            operator="+=",
            scope=scope,
            condition=condition,
            source=node.source,
            conditions=conditions,
            branch_path=branch_path,
        )

    # "=" and ":=" both use last-wins.
    directives[node.name] = effective


def _merge_append(prev_value: str, new_value: str) -> str:
    """Merge two values for the += operator.

    For parenthesized lists like ( "mod_a" ), concatenate the inner items.
    For plain strings, concatenate them.
    """
    prev_inner = _unwrap_paren_list(prev_value)
    new_inner = _unwrap_paren_list(new_value)

    if prev_inner is not None and new_inner is not None:
        items = []
        if prev_inner.strip():
            items.append(prev_inner.strip())
        if new_inner.strip():
            items.append(new_inner.strip())
        return "( " + ", ".join(items) + " )"

    # Fallback: plain string concatenation for non-parenthesized values.
    # Lighttpd += on non-list values is rare in practice; string concat
    # is a safe approximation for the common case.
    #
    # Only insert a space when both sides are non-empty — otherwise an
    # empty previous value turned ``"" + "foo"`` into ``" foo"`` (and
    # ``"foo" += ""`` into ``"foo "``), which rule code that compares
    # strings against literal tokens then reads as a different value.
    prev_clean = prev_value.strip()
    new_clean = new_value.strip()
    if not prev_clean:
        return new_clean
    if not new_clean:
        return prev_clean
    return prev_clean + " " + new_clean


def _unwrap_paren_list(value: str) -> str | None:
    stripped = value.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        return stripped[1:-1]
    return None


def merge_conditional_scopes(
    effective_config: LighttpdEffectiveConfig,
    context: LighttpdRequestContext | None = None,
) -> dict[str, LighttpdEffectiveDirective]:
    """Merge global directives with all potentially-matching conditional scopes.

    Returns a flat directive dict that represents the "effective" view for
    a given *context*.  When *context* is ``None`` every conditional scope
    is treated as potentially matching (worst-case static analysis).

    Merge order follows definition order — later scopes override earlier
    ones (last-wins), and ``+=`` appends are accumulated.

    **Nested condition chains** — every condition in
    ``scope.conditions`` must be potentially matching for the scope to
    be included.

    **else blocks** — an ``else`` scope is included only when its
    sibling ``if``-scope was *not* deterministically matched.  When the
    context is ``None`` (worst-case), both ``if`` and ``else`` are
    included because either branch could fire.
    """
    merged: dict[str, LighttpdEffectiveDirective] = dict(
        effective_config.global_directives,
    )

    scopes = effective_config.conditional_scopes
    # Pre-compute deterministic match results for if/else sibling logic.
    scope_deterministic: list[bool] = [
        _is_deterministic_match(s, context) for s in scopes
    ]
    append_accumulators: dict[str, list[LighttpdEffectiveDirective]] = {}

    for scope in scopes:
        if not _scope_matches(scope, scope_deterministic, context):
            continue
        for name, directive in scope.directives.items():
            if directive.operator == "+=" and context is None:
                merged[name] = _merge_worst_case_append(
                    name,
                    directive,
                    effective_config,
                    append_accumulators,
                )
            elif directive.operator == "+=" and name in merged:
                prev = merged[name]
                merged_value = _merge_append(prev.value, directive.value)
                merged[name] = LighttpdEffectiveDirective(
                    name=name,
                    value=merged_value,
                    operator="+=",
                    scope="merged",
                    condition=directive.condition,
                    source=directive.source,
                    conditions=directive.conditions,
                    branch_path=directive.branch_path,
                )
            else:
                merged[name] = directive
                if context is None and directive.operator in {"=", ":="}:
                    _record_worst_case_assignment(
                        name,
                        directive,
                        append_accumulators,
                    )

    return merged


def _merge_worst_case_append(
    name: str,
    directive: LighttpdEffectiveDirective,
    effective_config: LighttpdEffectiveConfig,
    append_accumulators: dict[str, list[LighttpdEffectiveDirective]],
) -> LighttpdEffectiveDirective:
    accumulators = append_accumulators.setdefault(name, [])
    compatible_index = _append_compatible_index(accumulators, directive)
    if compatible_index is not None:
        prev_value = accumulators[compatible_index].value
    else:
        base = _last_compatible_base_directive(name, directive, effective_config)
        if base is not None:
            accumulators.append(base)
            compatible_index = len(accumulators) - 1
        prev_value = base.value if base is not None else None

    merged_value = (
        _merge_append(prev_value, directive.value)
        if prev_value is not None
        else directive.value
    )
    merged = LighttpdEffectiveDirective(
        name=name,
        value=merged_value,
        operator="+=",
        scope="merged",
        condition=directive.condition,
        source=directive.source,
        conditions=directive.conditions,
        branch_path=directive.branch_path,
    )
    if compatible_index is None:
        accumulators.append(merged)
    else:
        accumulators[compatible_index] = merged
    return merged


def _record_worst_case_assignment(
    name: str,
    directive: LighttpdEffectiveDirective,
    append_accumulators: dict[str, list[LighttpdEffectiveDirective]],
) -> None:
    accumulators = append_accumulators.setdefault(name, [])
    compatible_index = _append_compatible_index(accumulators, directive)
    if compatible_index is None:
        accumulators.append(directive)
    else:
        accumulators[compatible_index] = directive


def _last_compatible_base_directive(
    name: str,
    directive: LighttpdEffectiveDirective,
    effective_config: LighttpdEffectiveConfig,
) -> LighttpdEffectiveDirective | None:
    candidates: list[LighttpdEffectiveDirective] = []
    global_directive = effective_config.global_directives.get(name)
    if global_directive is not None:
        candidates.append(global_directive)

    for scope in effective_config.conditional_scopes:
        candidate = scope.directives.get(name)
        if (
            candidate is not None
            and candidate.operator in {"=", ":="}
            and _source_before(candidate.source, directive.source)
            and _append_scope_compatible(candidate, directive)
        ):
            candidates.append(candidate)

    if not candidates:
        return None
    return max(candidates, key=lambda candidate: _source_sort_key(candidate.source))


def _source_before(
    previous: LighttpdSourceSpan,
    current: LighttpdSourceSpan,
) -> bool:
    if previous.line is None or current.line is None:
        return False
    if (
        (previous.file_path or current.file_path)
        and previous.file_path != current.file_path
    ):
        return False
    return previous.line < current.line


def _source_sort_key(source: LighttpdSourceSpan) -> tuple[str, int]:
    return (source.file_path or "", source.line or -1)


def _append_compatible_index(
    accumulators: list[LighttpdEffectiveDirective],
    current: LighttpdEffectiveDirective,
) -> int | None:
    for offset, accumulator in enumerate(reversed(accumulators)):
        if _append_scope_compatible(accumulator, current):
            return len(accumulators) - 1 - offset
    return None


def _append_scope_compatible(
    previous: LighttpdEffectiveDirective,
    current: LighttpdEffectiveDirective,
) -> bool:
    return not (
        _branch_paths_contradict(previous.branch_path, current.branch_path)
        or _condition_chains_contradict(previous.conditions, current.conditions)
    )


def _branch_paths_contradict(
    previous: tuple[tuple[int, int], ...],
    current: tuple[tuple[int, int], ...],
) -> bool:
    # Each nesting level appended by _collect_block contributes exactly one
    # entry with a fresh chain_id from the global counter, so chain_ids are
    # unique within a branch_path and dict() conversion is lossless.
    previous_branches = dict(previous)
    for chain_id, current_branch in current:
        previous_branch = previous_branches.get(chain_id)
        if previous_branch is not None and previous_branch != current_branch:
            return True
    return False


def _condition_chains_contradict(
    previous: tuple[LighttpdCondition | None, ...],
    current: tuple[LighttpdCondition | None, ...],
) -> bool:
    # Compare every concrete condition pair across both chains: a contradiction
    # on any shared variable means the scopes are mutually exclusive, even when
    # the chains nest the same variables in a different order.
    for previous_condition in previous:
        if previous_condition is None:
            continue
        for current_condition in current:
            if current_condition is None:
                continue
            if _conditions_contradict(previous_condition, current_condition):
                return True
    return False


_CONTRADICTION_HANDLERS: dict[tuple[str, str], Callable[[str, str], bool]] = {
    ("==", "=="): lambda previous, current: previous != current,
    ("==", "!="): lambda previous, current: previous == current,
    ("!=", "=="): lambda previous, current: previous == current,
    ("=^", "=^"): lambda previous, current: not _values_share_prefix(previous, current),
    ("=$", "=$"): lambda previous, current: not _values_share_suffix(previous, current),
    ("==", "=^"): lambda previous, current: not previous.startswith(current),
    ("==", "=$"): lambda previous, current: not previous.endswith(current),
    ("=^", "=="): lambda previous, current: not current.startswith(previous),
    ("=$", "=="): lambda previous, current: not current.endswith(previous),
}


def _conditions_contradict(
    previous: LighttpdCondition,
    current: LighttpdCondition,
) -> bool:
    if previous.variable != current.variable:
        return False
    handler = _CONTRADICTION_HANDLERS.get((previous.operator, current.operator))
    if handler is None:
        return False
    return handler(previous.value, current.value)


def _values_share_prefix(previous: str, current: str) -> bool:
    return previous.startswith(current) or current.startswith(previous)


def _values_share_suffix(previous: str, current: str) -> bool:
    return previous.endswith(current) or current.endswith(previous)


def _scope_matches(
    scope: LighttpdConditionalScope,
    scope_deterministic: list[bool],
    context: LighttpdRequestContext | None,
) -> bool:
    """Decide whether *scope* should participate in the merge."""
    # else-block: skip when the sibling if-scope was *deterministically*
    # matched (i.e. all its conditions evaluated to True, not just
    # "potentially matching").  In worst-case (no context) both if and
    # else branches must be included.
    branch_indices = scope.previous_branch_indices
    if not branch_indices and scope.is_else and scope.sibling_if_index >= 0:
        branch_indices = (scope.sibling_if_index,)
    if (
        (scope.is_else or scope.is_else_if)
        and branch_indices
        and any(scope_deterministic[index] for index in branch_indices)
    ):
        return False

    # Check the full condition chain (all ancestors + own condition).
    # When ``conditions`` is empty (e.g. manually constructed scope),
    # fall back to the single ``scope.condition``.
    conds = scope.conditions if scope.conditions else (scope.condition,)
    for cond in conds:
        if not is_potentially_matching(cond, context):
            return False
    return True


def _is_deterministic_match(
    scope: LighttpdConditionalScope,
    context: LighttpdRequestContext | None,
) -> bool:
    """Return True only when every condition in the chain evaluates to True
    (not just "potentially matching").  Requires a concrete context."""
    if context is None:
        return False
    from webconf_audit.local.lighttpd.conditions import evaluate_condition

    conds = scope.conditions if scope.conditions else (scope.condition,)
    for cond in conds:
        if cond is None:
            # None condition (else block) is not deterministic by itself.
            return False
        result = evaluate_condition(cond, context)
        if result is not True:
            return False
    return True


__all__ = [
    "LighttpdConditionalScope",
    "LighttpdEffectiveConfig",
    "LighttpdEffectiveDirective",
    "build_effective_config",
    "merge_conditional_scopes",
]
