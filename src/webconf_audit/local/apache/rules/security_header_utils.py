from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
    ApacheSourceSpan,
)
from webconf_audit.models import Finding, SourceLocation

_TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)
_IF_CHAIN_START_BLOCKS = frozenset({"if"})
_OPTIONAL_WRAPPER_BLOCKS = frozenset({"ifdefine", "ifmodule", "ifversion"})
_CONDITIONAL_CONTINUATION_BLOCKS = frozenset({"else", "elseif"})
_HEADER_CONDITIONS = ("always", "onsuccess")
_DEFAULT_HEADER_CONDITION = "onsuccess"
_HEADER_SET_ACTIONS = frozenset({"set", "setifempty", "add", "append", "merge"})
_HEADER_REMOVE_ACTIONS = frozenset({"unset"})
_HEADER_VALUE_TRAILERS = frozenset({"early", "always"})

HeaderCondition = Literal["always", "onsuccess"]
HeaderState = dict[HeaderCondition, list["ApacheHeaderSetting"]]


@dataclass(frozen=True, slots=True)
class ApacheHeaderSetting:
    name: str
    value: str | None
    source: ApacheSourceSpan
    action: str = "set"
    apply_index: int = -1


@dataclass(frozen=True, slots=True)
class ApacheHeaderOutcome:
    always: list[ApacheHeaderSetting]
    onsuccess: list[ApacheHeaderSetting]


@dataclass(frozen=True, slots=True)
class ApacheHeaderScope:
    label: str
    source: ApacheSourceSpan | None
    outcomes: list[ApacheHeaderOutcome]
    auditable: bool
    missing_possible: bool = False


@dataclass(frozen=True, slots=True)
class _HeaderCollection:
    outcomes: list[HeaderState]
    next_apply_index: int = 0


def missing_header_findings(
    config_ast: ApacheConfigAst,
    *,
    header_name: str,
    rule_id: str,
    title: str,
    description: str,
    recommendation: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_effective_header_scopes(config_ast, header_name):
        if not scope.auditable or not scope.missing_possible:
            continue
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity="low",
                description=f"{description} Scope: {scope.label}.",
                recommendation=recommendation,
                location=_scope_location(scope),
                metadata={"scope_name": scope.label},
            )
        )
    return findings


def unsafe_header_findings(
    config_ast: ApacheConfigAst,
    *,
    header_name: str,
    is_safe_value: Callable[[str | None], bool],
    rule_id: str,
    title: str,
    description: str,
    recommendation: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_effective_header_scopes(config_ast, header_name):
        if not scope.auditable:
            continue
        unsafe_outcome = _select_unsafe_outcome(scope.outcomes, is_safe_value)
        if unsafe_outcome is None:
            continue
        outcome, setting, reported_value = unsafe_outcome
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity="low",
                description=(
                    f"{description} Scope: {scope.label}; configured value: "
                    f"{reported_value or '<missing value>'}."
                ),
                recommendation=recommendation,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=setting.source.file_path,
                    line=setting.source.line,
                ),
                metadata={"scope_name": scope.label},
            )
        )
    return findings


def _select_unsafe_outcome(
    outcomes: list[ApacheHeaderOutcome],
    is_safe_value: Callable[[str | None], bool],
) -> tuple[ApacheHeaderOutcome, ApacheHeaderSetting, str] | None:
    for outcome in outcomes:
        for settings in (
            outcome.always,
            _success_response_settings(outcome),
        ):
            unsafe = _select_unsafe_settings(settings, is_safe_value)
            if unsafe is None:
                continue
            setting, reported = unsafe
            return outcome, setting, reported
    return None


def _select_unsafe_settings(
    settings: list[ApacheHeaderSetting],
    is_safe_value: Callable[[str | None], bool],
) -> tuple[ApacheHeaderSetting, str] | None:
    if not settings:
        return None
    unsafe_settings = [
        setting for setting in settings if not is_safe_value(setting.value)
    ]
    effective_value = _combine_effective_value(settings)
    combined_unsafe = not is_safe_value(effective_value)
    if not unsafe_settings and not combined_unsafe:
        return None
    setting = _last_applied_setting(unsafe_settings or settings)
    reported = setting.value if unsafe_settings else effective_value
    return setting, reported


def _last_applied_setting(
    settings: list[ApacheHeaderSetting],
) -> ApacheHeaderSetting:
    return max(settings, key=_source_order)


def _source_order(setting: ApacheHeaderSetting) -> int:
    return setting.apply_index


def _combine_effective_value(settings: list[ApacheHeaderSetting]) -> str:
    return ", ".join(
        setting.value for setting in settings if setting.value is not None
    )


def iter_effective_header_scopes(
    config_ast: ApacheConfigAst,
    header_name: str,
) -> list[ApacheHeaderScope]:
    virtualhosts = extract_virtualhost_contexts(config_ast)
    normalized_name = header_name.lower()

    global_collection = _collect_header_settings(config_ast.nodes, normalized_name)
    global_has_header_directive = _has_header_directive(config_ast.nodes)
    global_has_listen = _has_effective_listen(config_ast, None)

    global_scope = _build_scope(
        label="global",
        source=_first_source(config_ast.nodes),
        collection=global_collection,
        auditable=global_has_listen or global_has_header_directive,
    )

    scopes: list[ApacheHeaderScope] = [global_scope]
    for context in virtualhosts:
        collection = _collect_header_settings(
            context.node.children,
            normalized_name,
            initial=global_collection,
        )
        scopes.append(
            _build_scope(
                label=_virtualhost_label(context),
                source=context.node.source,
                collection=collection,
                auditable=(
                    _has_effective_listen(config_ast, context)
                    or _has_header_directive(context.node.children)
                ),
            )
        )
    return scopes


def _build_scope(
    *,
    label: str,
    source: ApacheSourceSpan | None,
    collection: _HeaderCollection,
    auditable: bool,
) -> ApacheHeaderScope:
    header_outcomes = [_split_header_state(state) for state in collection.outcomes]
    return ApacheHeaderScope(
        label=label,
        source=source,
        outcomes=header_outcomes,
        auditable=auditable,
        missing_possible=not any(outcome.always for outcome in header_outcomes),
    )


def _collect_header_settings(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    header_name: str,
    *,
    initial: _HeaderCollection | None = None,
) -> _HeaderCollection:
    collection = _clone_header_collection(initial)
    index = 0
    while index < len(nodes):
        node = nodes[index]
        if isinstance(node, ApacheBlockNode):
            block_name = node.name.lower()
            if block_name in _IF_CHAIN_START_BLOCKS:
                branches, index = _collect_conditional_chain(nodes, index)
                collection = _fork_conditional_branches(
                    collection,
                    branches,
                    header_name,
                )
                continue
            if block_name in _OPTIONAL_WRAPPER_BLOCKS:
                collection = _fork_conditional_branches(
                    collection,
                    [node],
                    header_name,
                )
                index += 1
                continue
            if block_name in _CONDITIONAL_CONTINUATION_BLOCKS:
                collection = _fork_conditional_branches(
                    collection,
                    [node],
                    header_name,
                )
                index += 1
                continue
            index += 1
            continue

        parsed = _parse_header_directive(node)
        if parsed is None or parsed[1] != header_name:
            index += 1
            continue

        action, name, value, condition = parsed
        collection = _apply_header_action(
            collection,
            action=action,
            name=name,
            value=value,
            source=node.source,
            condition=condition,
        )
        index += 1
    return collection


def _collect_conditional_chain(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    index: int,
) -> tuple[list[ApacheBlockNode], int]:
    branches = [nodes[index]]
    next_index = index + 1
    while next_index < len(nodes):
        next_node = nodes[next_index]
        if not isinstance(next_node, ApacheBlockNode):
            break
        if next_node.name.lower() not in _CONDITIONAL_CONTINUATION_BLOCKS:
            break
        branches.append(next_node)
        next_index += 1
    return branches, next_index


def _fork_conditional_branches(
    collection: _HeaderCollection,
    branches: list[ApacheBlockNode],
    header_name: str,
) -> _HeaderCollection:
    has_else = any(branch.name.lower() == "else" for branch in branches)
    forked: list[HeaderState] = []
    seen: set[tuple] = set()
    next_apply_index = collection.next_apply_index
    for outcome in collection.outcomes:
        starting = _HeaderCollection(
            outcomes=[_clone_header_state(outcome)],
            next_apply_index=collection.next_apply_index,
        )
        for branch in branches:
            branch_collection = _collect_header_settings(
                branch.children,
                header_name,
                initial=starting,
            )
            next_apply_index = max(
                next_apply_index,
                branch_collection.next_apply_index,
            )
            for branch_outcome in branch_collection.outcomes:
                _add_unique_state(forked, seen, branch_outcome)
        if not has_else:
            _add_unique_state(forked, seen, _clone_header_state(outcome))
    return _HeaderCollection(
        outcomes=forked or [_empty_header_state()],
        next_apply_index=next_apply_index,
    )


def _add_unique_state(
    outcomes: list[HeaderState],
    seen: set[tuple],
    state: HeaderState,
) -> None:
    key = _state_key(state)
    if key in seen:
        return
    seen.add(key)
    outcomes.append(state)


def _apply_header_action(
    collection: _HeaderCollection,
    *,
    action: str,
    name: str,
    value: str | None,
    source: ApacheSourceSpan,
    condition: HeaderCondition,
) -> _HeaderCollection:
    new_outcomes: list[HeaderState] = []
    seen: set[tuple] = set()
    for outcome in collection.outcomes:
        new_state = _apply_action_to_state(
            outcome,
            action=action,
            name=name,
            value=value,
            source=source,
            condition=condition,
            apply_index=collection.next_apply_index,
        )
        _add_unique_state(new_outcomes, seen, new_state)
    return _HeaderCollection(
        outcomes=new_outcomes,
        next_apply_index=collection.next_apply_index + 1,
    )


def _apply_action_to_state(
    state: HeaderState,
    *,
    action: str,
    name: str,
    value: str | None,
    source: ApacheSourceSpan,
    condition: HeaderCondition,
    apply_index: int,
) -> HeaderState:
    new_state = _clone_header_state(state)
    settings = new_state[condition]
    new_setting = ApacheHeaderSetting(
        name=name,
        value=value,
        source=source,
        action=action,
        apply_index=apply_index,
    )

    if action in _HEADER_REMOVE_ACTIONS:
        new_state[condition] = []
    elif action == "set":
        new_state[condition] = [new_setting]
    elif action == "setifempty":
        if not settings:
            settings.append(new_setting)
    elif action == "add":
        if not settings:
            settings.append(new_setting)
        else:
            new_state[condition] = _apply_combine_action(settings, action, new_setting)
    elif action in {"append", "merge"}:
        if not settings:
            settings.append(new_setting)
        else:
            new_state[condition] = _apply_combine_action(settings, action, new_setting)
    return new_state


def _apply_combine_action(
    settings: list[ApacheHeaderSetting],
    action: str,
    incoming: ApacheHeaderSetting,
) -> list[ApacheHeaderSetting]:
    new_value = (incoming.value or "").strip()
    updated: list[ApacheHeaderSetting] = []
    for instance in settings:
        existing = (instance.value or "").strip()
        if action == "merge":
            parts = [part.strip() for part in existing.split(",") if part.strip()]
            if new_value and new_value in parts:
                updated.append(instance)
                continue
        combined = f"{existing}, {new_value}" if existing else new_value
        updated.append(
            ApacheHeaderSetting(
                name=instance.name,
                value=combined,
                source=incoming.source,
                action=incoming.action,
                apply_index=incoming.apply_index,
            )
        )
    return updated


def _clone_header_collection(
    collection: _HeaderCollection | None,
) -> _HeaderCollection:
    if collection is None:
        return _HeaderCollection(outcomes=[_empty_header_state()])
    return _HeaderCollection(
        outcomes=[_clone_header_state(state) for state in collection.outcomes],
        next_apply_index=collection.next_apply_index,
    )


def _empty_header_state() -> HeaderState:
    return {"always": [], "onsuccess": []}


def _clone_header_state(state: HeaderState) -> HeaderState:
    return {
        condition: list(state.get(condition, []))
        for condition in _HEADER_CONDITIONS
    }


def _split_header_state(state: HeaderState) -> ApacheHeaderOutcome:
    return ApacheHeaderOutcome(
        always=_sorted_settings(state.get("always", [])),
        onsuccess=_sorted_settings(state.get("onsuccess", [])),
    )


def _flatten_header_outcome(
    outcome: ApacheHeaderOutcome,
) -> list[ApacheHeaderSetting]:
    return _sorted_settings([*outcome.always, *outcome.onsuccess])


def _success_response_settings(
    outcome: ApacheHeaderOutcome,
) -> list[ApacheHeaderSetting]:
    settings = _flatten_header_outcome(outcome)
    deduped: list[ApacheHeaderSetting] = []
    seen_values: set[tuple[str, str | None]] = set()
    for setting in settings:
        # Success responses can see both Apache header tables; identical
        # values are harmless for value-safety checks, conflicting values are not.
        key = (setting.name.lower(), _canonical_header_value(setting.value))
        if key in seen_values:
            continue
        seen_values.add(key)
        deduped.append(setting)
    return deduped


def _canonical_header_value(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip().strip('"').strip("'").lower()


def _sorted_settings(
    settings: list[ApacheHeaderSetting],
) -> list[ApacheHeaderSetting]:
    return sorted(settings, key=_source_order)


def _state_key(
    state: HeaderState,
) -> tuple[
    tuple[
        HeaderCondition,
        tuple[tuple[str, str | None, str, str | None, int | None, int], ...],
    ],
    ...,
]:
    return tuple(
        (
            condition,
            tuple(
                (
                    setting.name,
                    setting.value,
                    setting.action,
                    setting.source.file_path,
                    setting.source.line,
                    setting.apply_index,
                )
                for setting in state.get(condition, [])
            ),
        )
        for condition in _HEADER_CONDITIONS
    )


def _has_header_directive(nodes: list[ApacheDirectiveNode | ApacheBlockNode]) -> bool:
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() in _TRANSPARENT_WRAPPER_BLOCKS:
                if _has_header_directive(node.children):
                    return True
            continue
        if node.name.lower() == "header" and _parse_header_directive(node) is not None:
            return True
    return False


def _parse_header_directive(
    directive: ApacheDirectiveNode,
) -> tuple[str, str, str | None, HeaderCondition] | None:
    if directive.name.lower() != "header":
        return None
    args = directive.args
    if len(args) < 2:
        return None

    action_index = 0
    condition: HeaderCondition = _DEFAULT_HEADER_CONDITION
    first_arg = args[0].lower()
    if first_arg == "always":
        condition = "always"
        action_index = 1
    elif first_arg == "onsuccess":
        condition = "onsuccess"
        action_index = 1
    if len(args) <= action_index + 1:
        return None

    action = args[action_index].lower()
    if action not in _HEADER_SET_ACTIONS and action not in _HEADER_REMOVE_ACTIONS:
        return None

    header_name = args[action_index + 1].lower()
    value = _header_value(args[action_index + 2 :])
    return action, header_name, value, condition


def _header_value(args: list[str]) -> str | None:
    value_args: list[str] = []
    for arg in args:
        lowered = arg.lower()
        if lowered in _HEADER_VALUE_TRAILERS:
            continue
        if lowered.startswith("env=") or lowered.startswith("expr="):
            continue
        value_args.append(arg)

    if not value_args:
        return None
    return " ".join(value_args).strip().strip('"').strip("'")


def _has_effective_listen(
    config_ast: ApacheConfigAst,
    context: ApacheVirtualHostContext | None,
) -> bool:
    return "listen" in build_server_effective_config(
        config_ast,
        virtualhost_context=context,
    ).directives


def _virtualhost_label(context: ApacheVirtualHostContext) -> str:
    return context.server_name or context.listen_address or "<unnamed>"


def _first_source(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> ApacheSourceSpan | None:
    return nodes[0].source if nodes else None


def _scope_location(scope: ApacheHeaderScope) -> SourceLocation | None:
    if scope.source is None:
        return None
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=scope.source.file_path,
        line=scope.source.line,
    )


__all__ = [
    "ApacheHeaderScope",
    "ApacheHeaderSetting",
    "iter_effective_header_scopes",
    "missing_header_findings",
    "unsafe_header_findings",
]
