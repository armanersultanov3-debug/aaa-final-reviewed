from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Literal

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)

BUILTIN_LOG_FORMATS = frozenset({"common", "combined", "referer", "agent"})
CUSTOM_LOG_OPTION_PREFIXES = ("env=", "expr=")
FORMAT_NAME_DEFAULT = "<default>"
FORMAT_NAME_INLINE = "<inline>"

_TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)

ResolvedFormatKind = Literal[
    "inline",
    "named",
    "default",
    "builtin",
    "missing_named",
    "missing_default",
]


@dataclass(frozen=True, slots=True)
class ResolvedCustomLogFormat:
    context: ApacheVirtualHostContext | None
    custom_log: ApacheDirectiveNode
    format_name: str
    format_text: str | None
    kind: ResolvedFormatKind
    tls_enabled: bool


def defined_log_format_name(directive: ApacheDirectiveNode) -> str | None:
    if len(directive.args) < 2:
        return None
    return directive.args[-1]


def defined_log_format_text(directive: ApacheDirectiveNode) -> str:
    if len(directive.args) <= 2:
        return directive.args[0] if directive.args else ""
    return " ".join(directive.args[:-1])


def referenced_log_format_name(directive: ApacheDirectiveNode) -> str | None:
    if len(directive.args) < 2:
        return None
    if directive.args[0].lower() == "off":
        return None

    candidate = directive.args[1]
    if is_custom_log_option(candidate):
        return None
    if candidate.lower() in BUILTIN_LOG_FORMATS:
        return None
    if "%" in candidate:
        return None
    return candidate


def iter_effective_custom_log_formats(
    config_ast: ApacheConfigAst,
) -> Iterator[ResolvedCustomLogFormat]:
    server_directives = list(_iter_server_scope_directives(config_ast.nodes))
    server_formats = _collect_log_formats(server_directives)
    server_custom_logs = _custom_log_directives(server_directives)
    virtualhosts = extract_virtualhost_contexts(config_ast)

    if not virtualhosts:
        tls_enabled = _nodes_use_tls(config_ast.nodes)
        yield from _resolve_custom_logs(
            server_custom_logs,
            context=None,
            formats=server_formats,
            tls_enabled=tls_enabled,
        )
        return

    inherited_tls = _directives_use_tls(server_directives)
    for context in virtualhosts:
        vhost_directives = list(_iter_server_scope_directives(context.node.children))
        vhost_custom_logs = _custom_log_directives(vhost_directives)
        yield from _resolve_custom_logs(
            vhost_custom_logs or server_custom_logs,
            context=context,
            formats=server_formats.layered_with(_collect_log_formats(vhost_directives)),
            tls_enabled=inherited_tls or _nodes_use_tls(context.node.children),
        )


def is_custom_log_option(arg: str) -> bool:
    lowered = arg.lower()
    return any(lowered.startswith(prefix) for prefix in CUSTOM_LOG_OPTION_PREFIXES)


@dataclass(frozen=True, slots=True)
class _LogFormatScope:
    named: dict[str, str]
    default: str | None

    def layered_with(self, child: _LogFormatScope) -> _LogFormatScope:
        return _LogFormatScope(
            named={**self.named, **child.named},
            default=child.default if child.default is not None else self.default,
        )


def _collect_log_formats(directives: Iterable[ApacheDirectiveNode]) -> _LogFormatScope:
    named: dict[str, str] = {}
    default: str | None = None

    for directive in directives:
        if directive.name.lower() != "logformat":
            continue

        format_text = defined_log_format_text(directive)
        format_name = defined_log_format_name(directive)
        if format_name is None:
            default = format_text
            continue
        named[format_name] = format_text

    return _LogFormatScope(named=named, default=default)


def _custom_log_directives(
    directives: Iterable[ApacheDirectiveNode],
) -> list[ApacheDirectiveNode]:
    return [
        directive
        for directive in directives
        if directive.name.lower() == "customlog" and not _custom_log_is_off(directive)
    ]


def _custom_log_is_off(directive: ApacheDirectiveNode) -> bool:
    return bool(directive.args) and directive.args[0].lower() == "off"


def _resolve_custom_logs(
    custom_logs: Iterable[ApacheDirectiveNode],
    *,
    context: ApacheVirtualHostContext | None,
    formats: _LogFormatScope,
    tls_enabled: bool,
) -> Iterator[ResolvedCustomLogFormat]:
    for custom_log in custom_logs:
        yield _resolve_custom_log(
            custom_log,
            context=context,
            formats=formats,
            tls_enabled=tls_enabled,
        )


def _resolve_custom_log(
    custom_log: ApacheDirectiveNode,
    *,
    context: ApacheVirtualHostContext | None,
    formats: _LogFormatScope,
    tls_enabled: bool,
) -> ResolvedCustomLogFormat:
    candidate = _custom_log_format_arg(custom_log)
    if candidate is None:
        if formats.default is None:
            return ResolvedCustomLogFormat(
                context=context,
                custom_log=custom_log,
                format_name=FORMAT_NAME_DEFAULT,
                format_text=None,
                kind="missing_default",
                tls_enabled=tls_enabled,
            )
        return ResolvedCustomLogFormat(
            context=context,
            custom_log=custom_log,
            format_name=FORMAT_NAME_DEFAULT,
            format_text=formats.default,
            kind="default",
            tls_enabled=tls_enabled,
        )

    if "%" in candidate:
        return ResolvedCustomLogFormat(
            context=context,
            custom_log=custom_log,
            format_name=FORMAT_NAME_INLINE,
            format_text=candidate,
            kind="inline",
            tls_enabled=tls_enabled,
        )

    if candidate in formats.named:
        return ResolvedCustomLogFormat(
            context=context,
            custom_log=custom_log,
            format_name=candidate,
            format_text=formats.named[candidate],
            kind="named",
            tls_enabled=tls_enabled,
        )

    if candidate.lower() in BUILTIN_LOG_FORMATS:
        return ResolvedCustomLogFormat(
            context=context,
            custom_log=custom_log,
            format_name=candidate,
            format_text=None,
            kind="builtin",
            tls_enabled=tls_enabled,
        )

    return ResolvedCustomLogFormat(
        context=context,
        custom_log=custom_log,
        format_name=candidate,
        format_text=None,
        kind="missing_named",
        tls_enabled=tls_enabled,
    )


def _custom_log_format_arg(custom_log: ApacheDirectiveNode) -> str | None:
    if len(custom_log.args) < 2:
        return None

    candidate = custom_log.args[1]
    if is_custom_log_option(candidate):
        return None
    return candidate


def _iter_server_scope_directives(
    nodes: Iterable[ApacheDirectiveNode | ApacheBlockNode],
) -> Iterator[ApacheDirectiveNode]:
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            yield node
            continue

        if node.name.lower() in _TRANSPARENT_WRAPPER_BLOCKS:
            yield from _iter_server_scope_directives(node.children)


def _nodes_use_tls(nodes: Iterable[ApacheDirectiveNode | ApacheBlockNode]) -> bool:
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if _directive_uses_tls(node):
                return True
            continue
        if _nodes_use_tls(node.children):
            return True
    return False


def _directives_use_tls(directives: Iterable[ApacheDirectiveNode]) -> bool:
    return any(_directive_uses_tls(directive) for directive in directives)


def _directive_uses_tls(directive: ApacheDirectiveNode) -> bool:
    name = directive.name.lower()
    if name == "sslengine":
        return bool(directive.args) and directive.args[0].lower() == "on"
    return name in {"sslprotocol", "sslciphersuite", "sslcertificatefile"}


__all__ = [
    "BUILTIN_LOG_FORMATS",
    "CUSTOM_LOG_OPTION_PREFIXES",
    "FORMAT_NAME_DEFAULT",
    "FORMAT_NAME_INLINE",
    "ResolvedCustomLogFormat",
    "defined_log_format_name",
    "defined_log_format_text",
    "iter_effective_custom_log_formats",
    "is_custom_log_option",
    "referenced_log_format_name",
]
