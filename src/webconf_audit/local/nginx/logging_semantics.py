"""Reusable Nginx access/error logging semantics."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal

from webconf_audit.local.nginx.effective_scope import (
    NginxScope,
    NginxScopeGraph,
    NginxScopeKind,
)
from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, SourceSpan

AccessState = Literal["enabled", "off", "unknown"]
AccessConditionKind = Literal[
    "unconditional",
    "constant_true",
    "constant_false",
    "dynamic",
]
AccessDestinationKind = Literal[
    "file",
    "syslog",
    "stderr",
    "variable_path",
    "off",
    "unknown",
]
ErrorDestinationKind = Literal[
    "file",
    "syslog",
    "stderr",
    "memory",
    "null_device",
    "unknown",
]
EscapeMode = Literal["default", "json", "none"]
ErrorThreshold = Literal[
    "debug",
    "info",
    "notice",
    "warn",
    "error",
    "crit",
    "alert",
    "emerg",
]
DestinationOrigin = Literal["explicit", "inherited", "nginx_default"]

_ACCESS_LOG_OPTION_PREFIXES = ("buffer=", "flush=", "gzip=", "if=")
_ACCESS_ALLOWED_KINDS = frozenset(
    {
        NginxScopeKind.HTTP,
        NginxScopeKind.SERVER,
        NginxScopeKind.LOCATION,
        NginxScopeKind.IF_IN_LOCATION,
        NginxScopeKind.LIMIT_EXCEPT,
    }
)
_ERROR_ALLOWED_KINDS = frozenset(
    {
        NginxScopeKind.MAIN,
        NginxScopeKind.HTTP,
        NginxScopeKind.SERVER,
        NginxScopeKind.LOCATION,
    }
)
_ERROR_LEVELS: tuple[ErrorThreshold, ...] = (
    "debug",
    "info",
    "notice",
    "warn",
    "error",
    "crit",
    "alert",
    "emerg",
)
_NGINX_VARIABLE_RE = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z0-9_]+)\}|(?P<plain>[A-Za-z0-9_]+))"
)
_BUILTIN_COMBINED_VARIABLES = frozenset(
    {
        "$remote_addr",
        "$remote_user",
        "$time_local",
        "$request",
        "$status",
        "$body_bytes_sent",
        "$http_referer",
        "$http_user_agent",
    }
)


@dataclass(frozen=True, slots=True)
class AccessLogDestination:
    destination_kind: AccessDestinationKind
    raw_path: str
    format_name: str
    options: tuple[str, ...]
    condition: str | None
    condition_kind: AccessConditionKind
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str
    origin: DestinationOrigin


@dataclass(frozen=True, slots=True)
class LogFormatDefinition:
    name: str
    escape_mode: EscapeMode
    raw_tokens: tuple[str, ...]
    variables: frozenset[str]
    source: SourceSpan | None
    origin: Literal["explicit", "nginx_builtin"]


@dataclass(frozen=True, slots=True)
class ErrorLogDestination:
    destination_kind: ErrorDestinationKind
    raw_path: str
    threshold: ErrorThreshold
    json_mode: bool
    source: SourceSpan | None
    declared_scope_id: str
    effective_scope_id: str
    origin: DestinationOrigin


@dataclass(frozen=True, slots=True)
class EffectiveLoggingScope:
    scope_id: str
    access_state: AccessState
    access_logs: tuple[AccessLogDestination, ...]
    error_logs: tuple[ErrorLogDestination, ...]
    complete: bool
    indeterminate_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UnsupportedLoggingEvidence:
    reason: str
    directive_name: str
    scope_id: str
    source: SourceSpan
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class NginxLoggingSemantics:
    scope_graph: NginxScopeGraph
    format_definitions: dict[str, LogFormatDefinition]
    effective_scopes: tuple[EffectiveLoggingScope, ...]
    effective_scopes_by_id: dict[str, EffectiveLoggingScope]
    declared_access_scope_ids: frozenset[str]
    declared_error_scope_ids: frozenset[str]
    unsupported_evidence: tuple[UnsupportedLoggingEvidence, ...]


def resolve_logging_semantics(
    config_ast: ConfigAst,
    *,
    scope_graph: NginxScopeGraph,
) -> NginxLoggingSemantics:
    del config_ast
    unsupported: list[UnsupportedLoggingEvidence] = []
    current_access: dict[str, tuple[DirectiveNode, ...]] = {}
    current_error: dict[str, tuple[DirectiveNode, ...]] = {}
    format_definitions = _collect_log_formats(scope_graph, unsupported)

    for scope in scope_graph.scopes:
        directives = tuple(
            node
            for node in scope_graph.scope_nodes.get(scope.scope_id, ())
            if isinstance(node, DirectiveNode)
        )
        access_directives = tuple(
            directive for directive in directives if directive.name == "access_log"
        )
        error_directives = tuple(
            directive for directive in directives if directive.name == "error_log"
        )
        if access_directives:
            if scope.kind in _ACCESS_ALLOWED_KINDS:
                current_access[scope.scope_id] = access_directives
            else:
                unsupported.extend(
                    UnsupportedLoggingEvidence(
                        reason="illegal-context",
                        directive_name="access_log",
                        scope_id=scope.scope_id,
                        source=directive.source,
                    )
                    for directive in access_directives
                )
        if error_directives:
            if scope.kind in _ERROR_ALLOWED_KINDS:
                current_error[scope.scope_id] = error_directives
            else:
                unsupported.extend(
                    UnsupportedLoggingEvidence(
                        reason="illegal-context",
                        directive_name="error_log",
                        scope_id=scope.scope_id,
                        source=directive.source,
                    )
                    for directive in error_directives
                )

    effective_lookup: dict[str, EffectiveLoggingScope] = {}
    for scope in scope_graph.scopes:
        parent = (
            effective_lookup[scope.parent_id]
            if scope.parent_id is not None
            else None
        )
        access_state, access_logs, access_reasons = _resolve_access_scope(
            scope,
            parent=parent,
            current_directives=current_access.get(scope.scope_id, ()),
        )
        error_logs, error_reasons = _resolve_error_scope(
            scope,
            parent=parent,
            current_directives=current_error.get(scope.scope_id, ()),
        )
        reasons = tuple(
            sorted(
                set(scope.completeness_issues)
                | set(access_reasons)
                | set(error_reasons)
            )
        )
        effective_lookup[scope.scope_id] = EffectiveLoggingScope(
            scope_id=scope.scope_id,
            access_state=access_state,
            access_logs=access_logs,
            error_logs=error_logs,
            complete=scope.complete,
            indeterminate_reasons=reasons,
        )

    effective_scopes = tuple(
        effective_lookup[scope.scope_id]
        for scope in scope_graph.scopes
    )
    return NginxLoggingSemantics(
        scope_graph=scope_graph,
        format_definitions=format_definitions,
        effective_scopes=effective_scopes,
        effective_scopes_by_id=effective_lookup,
        declared_access_scope_ids=frozenset(current_access),
        declared_error_scope_ids=frozenset(current_error),
        unsupported_evidence=tuple(unsupported),
    )


def _collect_log_formats(
    scope_graph: NginxScopeGraph,
    unsupported: list[UnsupportedLoggingEvidence],
) -> dict[str, LogFormatDefinition]:
    definitions: dict[str, LogFormatDefinition] = {
        "combined": LogFormatDefinition(
            name="combined",
            escape_mode="default",
            raw_tokens=(),
            variables=_BUILTIN_COMBINED_VARIABLES,
            source=None,
            origin="nginx_builtin",
        )
    }
    for scope in scope_graph.scopes:
        for node in scope_graph.scope_nodes.get(scope.scope_id, ()):
            if not isinstance(node, DirectiveNode) or node.name != "log_format":
                continue
            if scope.kind != NginxScopeKind.HTTP:
                unsupported.append(
                    UnsupportedLoggingEvidence(
                        reason="illegal-context",
                        directive_name="log_format",
                        scope_id=scope.scope_id,
                        source=node.source,
                    )
                )
                continue
            if not node.args:
                unsupported.append(
                    UnsupportedLoggingEvidence(
                        reason="invalid-directive",
                        directive_name="log_format",
                        scope_id=scope.scope_id,
                        source=node.source,
                    )
                )
                continue
            name = node.args[0]
            escape_mode: EscapeMode = "default"
            raw_tokens = tuple(node.args[1:])
            if raw_tokens and raw_tokens[0].startswith("escape="):
                requested = raw_tokens[0].split("=", 1)[1].lower()
                if requested in {"default", "json", "none"}:
                    escape_mode = requested  # type: ignore[assignment]
                    raw_tokens = raw_tokens[1:]
                else:
                    unsupported.append(
                        UnsupportedLoggingEvidence(
                            reason="unknown-escape-mode",
                            directive_name="log_format",
                            scope_id=scope.scope_id,
                            source=node.source,
                            details=(requested,),
                        )
                    )
            definitions[name] = LogFormatDefinition(
                name=name,
                escape_mode=escape_mode,
                raw_tokens=raw_tokens,
                variables=frozenset(_extract_variables("".join(raw_tokens))),
                source=node.source,
                origin="explicit",
            )
    return definitions


def _resolve_access_scope(
    scope: NginxScope,
    *,
    parent: EffectiveLoggingScope | None,
    current_directives: tuple[DirectiveNode, ...],
) -> tuple[AccessState, tuple[AccessLogDestination, ...], tuple[str, ...]]:
    reasons: set[str] = set()
    if current_directives:
        has_off = any(_is_access_log_off(directive) for directive in current_directives)
        enabled_directives = tuple(
            directive for directive in current_directives if not _is_access_log_off(directive)
        )
        if has_off and enabled_directives:
            reasons.add("ambiguous_access_log_configuration")
            return "unknown", (), tuple(sorted(reasons))
        if has_off:
            return "off", (), ()
        if enabled_directives:
            return (
                "enabled",
                tuple(
                    _parse_access_destination(
                        directive,
                        declared_scope_id=scope.scope_id,
                        effective_scope_id=scope.scope_id,
                        origin="explicit",
                    )
                    for directive in enabled_directives
                ),
                (),
            )

    if scope.kind == NginxScopeKind.HTTP:
        return "enabled", (_default_access_log(scope.scope_id),), ()
    if parent is None:
        return "unknown", (), ()
    return (
        parent.access_state,
        tuple(
            _inherited_access_destination(destination, scope.scope_id)
            for destination in parent.access_logs
        ),
        (),
    )


def _resolve_error_scope(
    scope: NginxScope,
    *,
    parent: EffectiveLoggingScope | None,
    current_directives: tuple[DirectiveNode, ...],
) -> tuple[tuple[ErrorLogDestination, ...], tuple[str, ...]]:
    if current_directives:
        return (
            tuple(
                _parse_error_destination(
                    directive,
                    declared_scope_id=scope.scope_id,
                    effective_scope_id=scope.scope_id,
                    origin="explicit",
                )
                for directive in current_directives
            ),
            (),
        )

    if parent is None:
        return (_default_error_log(scope.scope_id),), ()
    return (
        tuple(
            _inherited_error_destination(destination, scope.scope_id)
            for destination in parent.error_logs
        ),
        (),
    )


def _parse_access_destination(
    directive: DirectiveNode,
    *,
    declared_scope_id: str,
    effective_scope_id: str,
    origin: DestinationOrigin,
) -> AccessLogDestination:
    if not directive.args:
        return AccessLogDestination(
            destination_kind="unknown",
            raw_path="",
            format_name="combined",
            options=(),
            condition=None,
            condition_kind="unconditional",
            source=directive.source,
            declared_scope_id=declared_scope_id,
            effective_scope_id=effective_scope_id,
            origin=origin,
        )

    raw_path = directive.args[0]
    format_name = "combined"
    options: list[str] = []
    if len(directive.args) >= 2 and not _is_access_log_option(directive.args[1]):
        format_name = directive.args[1]
        options.extend(directive.args[2:])
    else:
        options.extend(directive.args[1:])
    condition = next(
        (option.split("=", 1)[1] for option in options if option.startswith("if=")),
        None,
    )
    return AccessLogDestination(
        destination_kind=_classify_access_destination(raw_path),
        raw_path=raw_path,
        format_name=format_name,
        options=tuple(options),
        condition=condition,
        condition_kind=_classify_condition(condition),
        source=directive.source,
        declared_scope_id=declared_scope_id,
        effective_scope_id=effective_scope_id,
        origin=origin,
    )


def _parse_error_destination(
    directive: DirectiveNode,
    *,
    declared_scope_id: str,
    effective_scope_id: str,
    origin: DestinationOrigin,
) -> ErrorLogDestination:
    raw_path = directive.args[0] if directive.args else ""
    lowered_args = [arg.lower() for arg in directive.args[1:]]
    threshold: ErrorThreshold = next(
        (
            level
            for level in _ERROR_LEVELS
            if level in lowered_args
        ),
        "error",
    )
    return ErrorLogDestination(
        destination_kind=_classify_error_destination(raw_path),
        raw_path=raw_path,
        threshold=threshold,
        json_mode="json" in lowered_args,
        source=directive.source,
        declared_scope_id=declared_scope_id,
        effective_scope_id=effective_scope_id,
        origin=origin,
    )


def _default_access_log(scope_id: str) -> AccessLogDestination:
    return AccessLogDestination(
        destination_kind="file",
        raw_path="logs/access.log",
        format_name="combined",
        options=(),
        condition=None,
        condition_kind="unconditional",
        source=SourceSpan(file_path=None, line=1, column=1),
        declared_scope_id=scope_id,
        effective_scope_id=scope_id,
        origin="nginx_default",
    )


def _default_error_log(scope_id: str) -> ErrorLogDestination:
    return ErrorLogDestination(
        destination_kind="unknown",
        raw_path="",
        threshold="error",
        json_mode=False,
        source=None,
        declared_scope_id=scope_id,
        effective_scope_id=scope_id,
        origin="nginx_default",
    )


def _inherited_access_destination(
    destination: AccessLogDestination,
    effective_scope_id: str,
) -> AccessLogDestination:
    return AccessLogDestination(
        destination_kind=destination.destination_kind,
        raw_path=destination.raw_path,
        format_name=destination.format_name,
        options=destination.options,
        condition=destination.condition,
        condition_kind=destination.condition_kind,
        source=destination.source,
        declared_scope_id=destination.declared_scope_id,
        effective_scope_id=effective_scope_id,
        origin=(
            "nginx_default"
            if destination.origin == "nginx_default"
            else "inherited"
        ),
    )


def _inherited_error_destination(
    destination: ErrorLogDestination,
    effective_scope_id: str,
) -> ErrorLogDestination:
    return ErrorLogDestination(
        destination_kind=destination.destination_kind,
        raw_path=destination.raw_path,
        threshold=destination.threshold,
        json_mode=destination.json_mode,
        source=destination.source,
        declared_scope_id=destination.declared_scope_id,
        effective_scope_id=effective_scope_id,
        origin=(
            "nginx_default"
            if destination.origin == "nginx_default"
            else "inherited"
        ),
    )


def _is_access_log_off(directive: DirectiveNode) -> bool:
    return len(directive.args) == 1 and directive.args[0].lower() == "off"


def _is_access_log_option(arg: str) -> bool:
    lowered = arg.lower()
    return lowered == "gzip" or any(
        lowered.startswith(prefix) for prefix in _ACCESS_LOG_OPTION_PREFIXES
    )


def _classify_access_destination(raw_path: str) -> AccessDestinationKind:
    lowered = raw_path.lower()
    if lowered == "off":
        return "off"
    if lowered == "stderr":
        return "stderr"
    if lowered.startswith("syslog:"):
        return "syslog"
    if "$" in raw_path:
        return "variable_path"
    if raw_path:
        return "file"
    return "unknown"


def _classify_error_destination(raw_path: str) -> ErrorDestinationKind:
    lowered = raw_path.lower()
    if lowered == "stderr":
        return "stderr"
    if lowered == "/dev/null":
        return "null_device"
    if lowered.startswith("syslog:"):
        return "syslog"
    if lowered.startswith("memory:"):
        return "memory"
    if raw_path and "$" not in raw_path:
        return "file"
    return "unknown"


def _classify_condition(condition: str | None) -> AccessConditionKind:
    if condition is None:
        return "unconditional"
    stripped = condition.strip()
    if stripped in {"", "0"}:
        return "constant_false"
    if "$" in stripped:
        return "dynamic"
    return "constant_true"


def _extract_variables(format_text: str) -> set[str]:
    return {
        f"${match.group('braced') or match.group('plain')}"
        for match in _NGINX_VARIABLE_RE.finditer(format_text)
    }


__all__ = [
    "AccessLogDestination",
    "EffectiveLoggingScope",
    "ErrorLogDestination",
    "LogFormatDefinition",
    "NginxLoggingSemantics",
    "UnsupportedLoggingEvidence",
    "resolve_logging_semantics",
]
