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


@dataclass(frozen=True, slots=True)
class ApacheHeaderScope:
    label: str
    source: ApacheSourceSpan | None
    settings: list[ApacheHeaderSetting]
    auditable: bool
    missing_possible: bool = False


@dataclass(frozen=True, slots=True)
class _HeaderCollection:
    state: HeaderState
    missing_possible: bool


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
        if not scope.auditable or (scope.settings and not scope.missing_possible):
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
        if not scope.settings:
            continue
        unsafe_settings = [
            setting for setting in scope.settings if not is_safe_value(setting.value)
        ]
        if not unsafe_settings:
            continue
        setting = unsafe_settings[-1]
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity="low",
                description=(
                    f"{description} Scope: {scope.label}; configured value: "
                    f"{setting.value or '<missing value>'}."
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


def iter_effective_header_scopes(
    config_ast: ApacheConfigAst,
    header_name: str,
) -> list[ApacheHeaderScope]:
    virtualhosts = extract_virtualhost_contexts(config_ast)
    normalized_name = header_name.lower()

    global_collection = _collect_header_settings(config_ast.nodes, normalized_name)
    global_has_header_directive = _has_header_directive(config_ast.nodes)
    global_has_listen = _has_effective_listen(config_ast, None)

    if not virtualhosts:
        global_settings = _flatten_header_state(global_collection.state)
        return [
            ApacheHeaderScope(
                label="global",
                source=_first_source(config_ast.nodes),
                settings=global_settings,
                auditable=global_has_listen or global_has_header_directive,
                missing_possible=global_collection.missing_possible,
            )
        ]

    scopes: list[ApacheHeaderScope] = []
    for context in virtualhosts:
        collection = _collect_header_settings(
            context.node.children,
            normalized_name,
            initial=global_collection,
        )
        scopes.append(
            ApacheHeaderScope(
                label=_virtualhost_label(context),
                source=context.node.source,
                settings=_flatten_header_state(collection.state),
                auditable=(
                    _has_effective_listen(config_ast, context)
                    or _has_header_directive(context.node.children)
                ),
                missing_possible=collection.missing_possible,
            )
        )
    return scopes


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
                collection = _merge_conditional_branches(
                    collection,
                    branches,
                    header_name,
                )
                continue
            if block_name in _OPTIONAL_WRAPPER_BLOCKS:
                collection = _merge_conditional_branches(
                    collection,
                    [node],
                    header_name,
                )
                index += 1
                continue
            if block_name in _CONDITIONAL_CONTINUATION_BLOCKS:
                collection = _merge_conditional_branches(
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


def _merge_conditional_branches(
    collection: _HeaderCollection,
    branches: list[ApacheBlockNode],
    header_name: str,
) -> _HeaderCollection:
    outcomes: list[_HeaderCollection] = [
        _collect_header_settings(
            branch.children,
            header_name,
            initial=collection,
        )
        for branch in branches
    ]
    has_else = any(branch.name.lower() == "else" for branch in branches)
    if not has_else:
        outcomes.append(collection)

    return _HeaderCollection(
        state=_merge_header_states([outcome.state for outcome in outcomes]),
        missing_possible=any(
            outcome.missing_possible or not _state_has_settings(outcome.state)
            for outcome in outcomes
        ),
    )


def _apply_header_action(
    collection: _HeaderCollection,
    *,
    action: str,
    name: str,
    value: str | None,
    source: ApacheSourceSpan,
    condition: HeaderCondition,
) -> _HeaderCollection:
    state = _clone_header_state(collection.state)
    settings = state[condition]
    new_setting = ApacheHeaderSetting(
        name=name, value=value, source=source, action=action
    )

    if action in _HEADER_REMOVE_ACTIONS:
        state[condition] = []
    elif action == "set":
        state[condition] = [new_setting]
    elif action == "setifempty":
        if not settings or collection.missing_possible:
            settings.append(new_setting)
    elif action in {"add", "append", "merge"}:
        if not settings:
            settings.append(new_setting)
        else:
            state[condition] = _apply_combine_action(settings, action, new_setting)

    return _HeaderCollection(
        state=state,
        missing_possible=not _state_has_settings(state),
    )


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
            )
        )
    return updated


def _clone_header_collection(
    collection: _HeaderCollection | None,
) -> _HeaderCollection:
    if collection is None:
        state = _empty_header_state()
        return _HeaderCollection(state=state, missing_possible=True)
    return _HeaderCollection(
        state=_clone_header_state(collection.state),
        missing_possible=collection.missing_possible,
    )


def _empty_header_state() -> HeaderState:
    return {"always": [], "onsuccess": []}


def _clone_header_state(state: HeaderState) -> HeaderState:
    return {
        condition: list(state.get(condition, []))
        for condition in _HEADER_CONDITIONS
    }


def _merge_header_states(states: list[HeaderState]) -> HeaderState:
    merged = _empty_header_state()
    seen: set[
        tuple[HeaderCondition, str, str | None, str, str | None, int | None]
    ] = set()
    for state in states:
        for condition in _HEADER_CONDITIONS:
            for setting in state.get(condition, []):
                key = (
                    condition,
                    setting.name,
                    setting.value,
                    setting.action,
                    setting.source.file_path,
                    setting.source.line,
                )
                if key in seen:
                    continue
                seen.add(key)
                merged[condition].append(setting)
    return merged


def _flatten_header_state(state: HeaderState) -> list[ApacheHeaderSetting]:
    return [
        setting
        for condition in _HEADER_CONDITIONS
        for setting in state.get(condition, [])
    ]


def _state_has_settings(state: HeaderState) -> bool:
    return any(state.get(condition) for condition in _HEADER_CONDITIONS)


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
