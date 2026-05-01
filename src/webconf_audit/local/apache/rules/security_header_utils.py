from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

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
_HEADER_CONDITIONS = frozenset({"always", "onsuccess"})
_HEADER_SET_ACTIONS = frozenset({"set", "setifempty", "add", "append", "merge"})
_HEADER_REMOVE_ACTIONS = frozenset({"unset"})
_HEADER_VALUE_TRAILERS = frozenset({"early", "always"})


@dataclass(frozen=True, slots=True)
class ApacheHeaderSetting:
    name: str
    value: str | None
    source: ApacheSourceSpan


@dataclass(frozen=True, slots=True)
class ApacheHeaderScope:
    label: str
    source: ApacheSourceSpan | None
    settings: list[ApacheHeaderSetting]
    auditable: bool


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
        if not scope.auditable or scope.settings:
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

    global_state = _collect_header_settings(config_ast.nodes, normalized_name)
    global_has_header_directive = _has_header_directive(config_ast.nodes)
    global_has_listen = _has_effective_listen(config_ast, None)

    if not virtualhosts:
        return [
            ApacheHeaderScope(
                label="global",
                source=_first_source(config_ast.nodes),
                settings=global_state,
                auditable=global_has_listen or global_has_header_directive,
            )
        ]

    scopes: list[ApacheHeaderScope] = []
    for context in virtualhosts:
        settings = _collect_header_settings(
            context.node.children,
            normalized_name,
            initial=global_state,
        )
        scopes.append(
            ApacheHeaderScope(
                label=_virtualhost_label(context),
                source=context.node.source,
                settings=settings,
                auditable=True,
            )
        )
    return scopes


def _collect_header_settings(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    header_name: str,
    *,
    initial: list[ApacheHeaderSetting] | None = None,
) -> list[ApacheHeaderSetting]:
    settings = list(initial or [])
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() in _TRANSPARENT_WRAPPER_BLOCKS:
                settings = _collect_header_settings(
                    node.children,
                    header_name,
                    initial=settings,
                )
            continue

        parsed = _parse_header_directive(node)
        if parsed is None or parsed[1] != header_name:
            continue

        action, name, value = parsed
        if action in _HEADER_REMOVE_ACTIONS:
            settings = []
        elif action == "set":
            settings = [ApacheHeaderSetting(name=name, value=value, source=node.source)]
        elif action == "setifempty":
            if not settings:
                settings = [
                    ApacheHeaderSetting(name=name, value=value, source=node.source)
                ]
        elif action in {"add", "append", "merge"}:
            settings.append(
                ApacheHeaderSetting(name=name, value=value, source=node.source)
            )
    return settings


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
) -> tuple[str, str, str | None] | None:
    if directive.name.lower() != "header":
        return None
    args = directive.args
    if len(args) < 2:
        return None

    action_index = 0
    if args[0].lower() in _HEADER_CONDITIONS:
        action_index = 1
    if len(args) <= action_index + 1:
        return None

    action = args[action_index].lower()
    if action not in _HEADER_SET_ACTIONS and action not in _HEADER_REMOVE_ACTIONS:
        return None

    header_name = args[action_index + 1].lower()
    value = _header_value(args[action_index + 2 :])
    return action, header_name, value


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
