"""Reusable Nginx request/connection rate-limit semantics."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from fractions import Fraction
import re
from typing import Literal

from webconf_audit.local.nginx.effective_scope import (
    NginxScope,
    NginxScopeGraph,
    NginxScopeKind,
)
from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, SourceSpan

RateLimitLogLevel = Literal[
    "debug",
    "info",
    "notice",
    "warn",
    "error",
    "crit",
    "alert",
    "emerg",
]
DestinationOrigin = Literal["explicit", "inherited"]

_LEGAL_ZONE_SCOPE_KINDS = frozenset({NginxScopeKind.HTTP})
_LEGAL_LIMIT_SCOPE_KINDS = frozenset(
    {
        NginxScopeKind.HTTP,
        NginxScopeKind.SERVER,
        NginxScopeKind.LOCATION,
    }
)
_LEGAL_SCALAR_SCOPE_KINDS = _LEGAL_LIMIT_SCOPE_KINDS
_RATE_RE = re.compile(r"^(?P<value>\d+)r/(?P<unit>s|m)$", re.IGNORECASE)
_SIZE_RE = re.compile(r"^(?P<value>\d+)(?P<unit>[kmg])?$", re.IGNORECASE)
_LOG_LEVELS: tuple[RateLimitLogLevel, ...] = (
    "debug",
    "info",
    "notice",
    "warn",
    "error",
    "crit",
    "alert",
    "emerg",
)


@dataclass(frozen=True, slots=True)
class RequestRate:
    requests: int
    period_seconds: int

    @property
    def requests_per_second(self) -> Fraction:
        return Fraction(self.requests, self.period_seconds)


@dataclass(frozen=True, slots=True)
class LimitReqZoneDefinition:
    name: str
    key_tokens: tuple[str, ...]
    normalized_key: str
    size_bytes: int
    rate: RequestRate
    sync: bool
    source: SourceSpan


@dataclass(frozen=True, slots=True)
class LimitConnZoneDefinition:
    name: str
    key_tokens: tuple[str, ...]
    normalized_key: str
    size_bytes: int
    source: SourceSpan


@dataclass(frozen=True, slots=True)
class EffectiveLimitReq:
    zone_name: str
    burst: int
    delay: int | None
    nodelay: bool
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str
    origin: DestinationOrigin


@dataclass(frozen=True, slots=True)
class EffectiveLimitConn:
    zone_name: str
    connections: int
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str
    origin: DestinationOrigin


@dataclass(frozen=True, slots=True)
class EffectiveRateLimitScope:
    scope_id: str
    request_limits: tuple[EffectiveLimitReq, ...]
    connection_limits: tuple[EffectiveLimitConn, ...]
    request_dry_run: bool
    connection_dry_run: bool
    request_status: int
    connection_status: int
    request_log_level: RateLimitLogLevel
    connection_log_level: RateLimitLogLevel
    complete: bool
    indeterminate_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UnsupportedRateLimitEvidence:
    reason: str
    directive_name: str
    scope_id: str
    source: SourceSpan
    details: tuple[str, ...] = ()
    zone_name: str | None = None


@dataclass(frozen=True, slots=True)
class NginxRateLimitSemantics:
    scope_graph: NginxScopeGraph
    request_zones_by_name: dict[str, LimitReqZoneDefinition]
    connection_zones_by_name: dict[str, LimitConnZoneDefinition]
    effective_scopes: tuple[EffectiveRateLimitScope, ...]
    effective_scopes_by_id: dict[str, EffectiveRateLimitScope]
    unsupported_evidence: tuple[UnsupportedRateLimitEvidence, ...]


def resolve_rate_limit_semantics(
    config_ast: ConfigAst,
    *,
    scope_graph: NginxScopeGraph,
) -> NginxRateLimitSemantics:
    del config_ast
    unsupported: list[UnsupportedRateLimitEvidence] = []
    request_zone_candidates: dict[str, list[LimitReqZoneDefinition]] = defaultdict(list)
    connection_zone_candidates: dict[str, list[LimitConnZoneDefinition]] = defaultdict(list)

    for scope in scope_graph.scopes:
        directives = tuple(
            node
            for node in scope_graph.scope_nodes.get(scope.scope_id, ())
            if isinstance(node, DirectiveNode)
        )
        for directive in directives:
            if directive.name == "limit_req_zone":
                parsed = _parse_limit_req_zone(directive)
                if scope.kind not in _LEGAL_ZONE_SCOPE_KINDS:
                    unsupported.append(
                        UnsupportedRateLimitEvidence(
                            reason="illegal-context",
                            directive_name="limit_req_zone",
                            scope_id=scope.scope_id,
                            source=directive.source,
                        )
                    )
                    continue
                if parsed is None:
                    unsupported.append(
                        UnsupportedRateLimitEvidence(
                            reason="invalid-zone-definition",
                            directive_name="limit_req_zone",
                            scope_id=scope.scope_id,
                            source=directive.source,
                        )
                    )
                    continue
                request_zone_candidates[parsed.name].append(parsed)
            elif directive.name == "limit_conn_zone":
                parsed = _parse_limit_conn_zone(directive)
                if scope.kind not in _LEGAL_ZONE_SCOPE_KINDS:
                    unsupported.append(
                        UnsupportedRateLimitEvidence(
                            reason="illegal-context",
                            directive_name="limit_conn_zone",
                            scope_id=scope.scope_id,
                            source=directive.source,
                        )
                    )
                    continue
                if parsed is None:
                    unsupported.append(
                        UnsupportedRateLimitEvidence(
                            reason="invalid-zone-definition",
                            directive_name="limit_conn_zone",
                            scope_id=scope.scope_id,
                            source=directive.source,
                        )
                    )
                    continue
                connection_zone_candidates[parsed.name].append(parsed)

    request_zones_by_name = _finalize_request_zones(
        request_zone_candidates,
        unsupported=unsupported,
    )
    connection_zones_by_name = _finalize_connection_zones(
        connection_zone_candidates,
        unsupported=unsupported,
    )

    effective_lookup: dict[str, EffectiveRateLimitScope] = {}
    for scope in scope_graph.scopes:
        request_limits, request_reasons = _resolve_effective_limit_req(
            scope.scope_id,
            scope_graph=scope_graph,
            unsupported=unsupported,
        )
        connection_limits, connection_reasons = _resolve_effective_limit_conn(
            scope.scope_id,
            scope_graph=scope_graph,
            unsupported=unsupported,
        )
        request_dry_run, request_dry_run_reasons = _resolve_boolean_scalar(
            scope.scope_id,
            scope_graph=scope_graph,
            directive_name="limit_req_dry_run",
            default=False,
            unsupported=unsupported,
        )
        connection_dry_run, connection_dry_run_reasons = _resolve_boolean_scalar(
            scope.scope_id,
            scope_graph=scope_graph,
            directive_name="limit_conn_dry_run",
            default=False,
            unsupported=unsupported,
        )
        request_status, request_status_reasons = _resolve_status_scalar(
            scope.scope_id,
            scope_graph=scope_graph,
            directive_name="limit_req_status",
            default=503,
            unsupported=unsupported,
        )
        connection_status, connection_status_reasons = _resolve_status_scalar(
            scope.scope_id,
            scope_graph=scope_graph,
            directive_name="limit_conn_status",
            default=503,
            unsupported=unsupported,
        )
        request_log_level, request_log_level_reasons = _resolve_log_level_scalar(
            scope.scope_id,
            scope_graph=scope_graph,
            directive_name="limit_req_log_level",
            default="error",
            unsupported=unsupported,
        )
        connection_log_level, connection_log_level_reasons = _resolve_log_level_scalar(
            scope.scope_id,
            scope_graph=scope_graph,
            directive_name="limit_conn_log_level",
            default="error",
            unsupported=unsupported,
        )
        reasons = set(scope.completeness_issues)
        reasons.update(request_reasons)
        reasons.update(connection_reasons)
        reasons.update(request_dry_run_reasons)
        reasons.update(connection_dry_run_reasons)
        reasons.update(request_status_reasons)
        reasons.update(connection_status_reasons)
        reasons.update(request_log_level_reasons)
        reasons.update(connection_log_level_reasons)
        for entry in request_limits:
            if entry.zone_name not in request_zones_by_name:
                reasons.add("request-zone-definition-unresolved")
        for entry in connection_limits:
            if entry.zone_name not in connection_zones_by_name:
                reasons.add("connection-zone-definition-unresolved")
        effective_lookup[scope.scope_id] = EffectiveRateLimitScope(
            scope_id=scope.scope_id,
            request_limits=request_limits,
            connection_limits=connection_limits,
            request_dry_run=request_dry_run,
            connection_dry_run=connection_dry_run,
            request_status=request_status,
            connection_status=connection_status,
            request_log_level=request_log_level,
            connection_log_level=connection_log_level,
            complete=scope.complete,
            indeterminate_reasons=tuple(sorted(reasons)),
        )

    return NginxRateLimitSemantics(
        scope_graph=scope_graph,
        request_zones_by_name=request_zones_by_name,
        connection_zones_by_name=connection_zones_by_name,
        effective_scopes=tuple(effective_lookup[scope.scope_id] for scope in scope_graph.scopes),
        effective_scopes_by_id=effective_lookup,
        unsupported_evidence=tuple(unsupported),
    )


def _parse_limit_req_zone(directive: DirectiveNode) -> LimitReqZoneDefinition | None:
    zone_name: str | None = None
    size_bytes: int | None = None
    rate: RequestRate | None = None
    key_tokens: list[str] = []
    sync = False
    for arg in directive.args:
        if arg.startswith("zone="):
            if zone_name is not None:
                return None
            zone_name, size_bytes = _parse_zone_option(arg)
            if zone_name is None or size_bytes is None:
                return None
        elif arg.startswith("rate="):
            if rate is not None:
                return None
            parsed_rate = _parse_rate(arg.removeprefix("rate="))
            if parsed_rate is None:
                return None
            rate = parsed_rate
        elif arg == "sync":
            sync = True
        else:
            key_tokens.append(arg)
    if not key_tokens or zone_name is None or size_bytes is None or rate is None:
        return None
    return LimitReqZoneDefinition(
        name=zone_name,
        key_tokens=tuple(key_tokens),
        normalized_key=_normalize_expression(" ".join(key_tokens)),
        size_bytes=size_bytes,
        rate=rate,
        sync=sync,
        source=directive.source,
    )


def _parse_limit_conn_zone(directive: DirectiveNode) -> LimitConnZoneDefinition | None:
    zone_name: str | None = None
    size_bytes: int | None = None
    key_tokens: list[str] = []
    for arg in directive.args:
        if arg.startswith("zone="):
            if zone_name is not None:
                return None
            zone_name, size_bytes = _parse_zone_option(arg)
            if zone_name is None or size_bytes is None:
                return None
        else:
            key_tokens.append(arg)
    if not key_tokens or zone_name is None or size_bytes is None:
        return None
    return LimitConnZoneDefinition(
        name=zone_name,
        key_tokens=tuple(key_tokens),
        normalized_key=_normalize_expression(" ".join(key_tokens)),
        size_bytes=size_bytes,
        source=directive.source,
    )


def _parse_zone_option(value: str) -> tuple[str | None, int | None]:
    payload = value.removeprefix("zone=")
    if ":" not in payload:
        return None, None
    zone_name, raw_size = payload.split(":", 1)
    if not zone_name:
        return None, None
    return zone_name, _parse_size(raw_size)


def _parse_rate(value: str) -> RequestRate | None:
    match = _RATE_RE.fullmatch(value)
    if match is None:
        return None
    requests = int(match.group("value"), 10)
    period_seconds = 1 if match.group("unit").lower() == "s" else 60
    if requests <= 0:
        return None
    return RequestRate(requests=requests, period_seconds=period_seconds)


def _parse_size(value: str) -> int | None:
    match = _SIZE_RE.fullmatch(value)
    if match is None:
        return None
    parsed = int(match.group("value"), 10)
    unit = match.group("unit")
    multiplier = {
        None: 1,
        "k": 1024,
        "m": 1024 * 1024,
        "g": 1024 * 1024 * 1024,
    }[unit.lower() if unit is not None else None]
    if parsed <= 0:
        return None
    return parsed * multiplier


def _finalize_request_zones(
    zones_by_name: dict[str, list[LimitReqZoneDefinition]],
    *,
    unsupported: list[UnsupportedRateLimitEvidence],
) -> dict[str, LimitReqZoneDefinition]:
    finalized: dict[str, LimitReqZoneDefinition] = {}
    for zone_name, definitions in zones_by_name.items():
        first = definitions[0]
        if all(_same_request_zone(first, other) for other in definitions[1:]):
            finalized[zone_name] = first
            continue
        for definition in definitions:
            unsupported.append(
                UnsupportedRateLimitEvidence(
                    reason="duplicate-incompatible-zone-definition",
                    directive_name="limit_req_zone",
                    scope_id="http",
                    source=definition.source,
                    zone_name=zone_name,
                )
            )
    return finalized


def _finalize_connection_zones(
    zones_by_name: dict[str, list[LimitConnZoneDefinition]],
    *,
    unsupported: list[UnsupportedRateLimitEvidence],
) -> dict[str, LimitConnZoneDefinition]:
    finalized: dict[str, LimitConnZoneDefinition] = {}
    for zone_name, definitions in zones_by_name.items():
        first = definitions[0]
        if all(_same_connection_zone(first, other) for other in definitions[1:]):
            finalized[zone_name] = first
            continue
        for definition in definitions:
            unsupported.append(
                UnsupportedRateLimitEvidence(
                    reason="duplicate-incompatible-zone-definition",
                    directive_name="limit_conn_zone",
                    scope_id="http",
                    source=definition.source,
                    zone_name=zone_name,
                )
            )
    return finalized


def _same_request_zone(left: LimitReqZoneDefinition, right: LimitReqZoneDefinition) -> bool:
    return (
        left.normalized_key == right.normalized_key
        and left.size_bytes == right.size_bytes
        and left.rate.requests == right.rate.requests
        and left.rate.period_seconds == right.rate.period_seconds
        and left.sync == right.sync
    )


def _same_connection_zone(left: LimitConnZoneDefinition, right: LimitConnZoneDefinition) -> bool:
    return (
        left.normalized_key == right.normalized_key
        and left.size_bytes == right.size_bytes
    )


def _resolve_effective_limit_req(
    scope_id: str,
    *,
    scope_graph: NginxScopeGraph,
    unsupported: list[UnsupportedRateLimitEvidence],
) -> tuple[tuple[EffectiveLimitReq, ...], tuple[str, ...]]:
    reasons: set[str] = set()
    for scope in scope_graph.parent_chain(scope_id):
        if scope.kind not in _LEGAL_LIMIT_SCOPE_KINDS:
            _record_illegal_directives(scope, scope_graph, "limit_req", unsupported)
            continue
        directives = _directives_for_scope(scope_graph, scope.scope_id, "limit_req")
        if not directives:
            continue
        parsed: list[EffectiveLimitReq] = []
        invalid = False
        for directive in directives:
            entry = _parse_limit_req_usage(
                directive,
                declared_scope_id=scope.scope_id,
                effective_scope_id=scope_id,
                origin="explicit" if scope.scope_id == scope_id else "inherited",
            )
            if entry is None:
                invalid = True
                unsupported.append(
                    UnsupportedRateLimitEvidence(
                        reason="invalid-usage",
                        directive_name="limit_req",
                        scope_id=scope.scope_id,
                        source=directive.source,
                    )
                )
                continue
            parsed.append(entry)
        if invalid:
            reasons.add("invalid-limit-req-usage")
        return tuple(parsed), tuple(sorted(reasons))
    return (), ()


def _resolve_effective_limit_conn(
    scope_id: str,
    *,
    scope_graph: NginxScopeGraph,
    unsupported: list[UnsupportedRateLimitEvidence],
) -> tuple[tuple[EffectiveLimitConn, ...], tuple[str, ...]]:
    reasons: set[str] = set()
    for scope in scope_graph.parent_chain(scope_id):
        if scope.kind not in _LEGAL_LIMIT_SCOPE_KINDS:
            _record_illegal_directives(scope, scope_graph, "limit_conn", unsupported)
            continue
        directives = _directives_for_scope(scope_graph, scope.scope_id, "limit_conn")
        if not directives:
            continue
        parsed: list[EffectiveLimitConn] = []
        invalid = False
        for directive in directives:
            entry = _parse_limit_conn_usage(
                directive,
                declared_scope_id=scope.scope_id,
                effective_scope_id=scope_id,
                origin="explicit" if scope.scope_id == scope_id else "inherited",
            )
            if entry is None:
                invalid = True
                unsupported.append(
                    UnsupportedRateLimitEvidence(
                        reason="invalid-usage",
                        directive_name="limit_conn",
                        scope_id=scope.scope_id,
                        source=directive.source,
                    )
                )
                continue
            parsed.append(entry)
        if invalid:
            reasons.add("invalid-limit-conn-usage")
        return tuple(parsed), tuple(sorted(reasons))
    return (), ()


def _resolve_boolean_scalar(
    scope_id: str,
    *,
    scope_graph: NginxScopeGraph,
    directive_name: str,
    default: bool,
    unsupported: list[UnsupportedRateLimitEvidence],
) -> tuple[bool, tuple[str, ...]]:
    for scope in scope_graph.parent_chain(scope_id):
        if scope.kind not in _LEGAL_SCALAR_SCOPE_KINDS:
            _record_illegal_directives(scope, scope_graph, directive_name, unsupported)
            continue
        directives = _directives_for_scope(scope_graph, scope.scope_id, directive_name)
        if not directives:
            continue
        directive = directives[-1]
        if not directive.args or directive.args[0].lower() not in {"on", "off"}:
            unsupported.append(
                UnsupportedRateLimitEvidence(
                    reason="invalid-scalar",
                    directive_name=directive_name,
                    scope_id=scope.scope_id,
                    source=directive.source,
                )
            )
            return default, (f"invalid-{directive_name}",)
        return directive.args[0].lower() == "on", ()
    return default, ()


def _resolve_status_scalar(
    scope_id: str,
    *,
    scope_graph: NginxScopeGraph,
    directive_name: str,
    default: int,
    unsupported: list[UnsupportedRateLimitEvidence],
) -> tuple[int, tuple[str, ...]]:
    for scope in scope_graph.parent_chain(scope_id):
        if scope.kind not in _LEGAL_SCALAR_SCOPE_KINDS:
            _record_illegal_directives(scope, scope_graph, directive_name, unsupported)
            continue
        directives = _directives_for_scope(scope_graph, scope.scope_id, directive_name)
        if not directives:
            continue
        directive = directives[-1]
        if not directive.args:
            unsupported.append(
                UnsupportedRateLimitEvidence(
                    reason="invalid-scalar",
                    directive_name=directive_name,
                    scope_id=scope.scope_id,
                    source=directive.source,
                )
            )
            return default, (f"invalid-{directive_name}",)
        try:
            parsed = int(directive.args[0], 10)
        except ValueError:
            parsed = -1
        if parsed < 100 or parsed > 599:
            unsupported.append(
                UnsupportedRateLimitEvidence(
                    reason="invalid-scalar",
                    directive_name=directive_name,
                    scope_id=scope.scope_id,
                    source=directive.source,
                )
            )
            return default, (f"invalid-{directive_name}",)
        return parsed, ()
    return default, ()


def _resolve_log_level_scalar(
    scope_id: str,
    *,
    scope_graph: NginxScopeGraph,
    directive_name: str,
    default: RateLimitLogLevel,
    unsupported: list[UnsupportedRateLimitEvidence],
) -> tuple[RateLimitLogLevel, tuple[str, ...]]:
    for scope in scope_graph.parent_chain(scope_id):
        if scope.kind not in _LEGAL_SCALAR_SCOPE_KINDS:
            _record_illegal_directives(scope, scope_graph, directive_name, unsupported)
            continue
        directives = _directives_for_scope(scope_graph, scope.scope_id, directive_name)
        if not directives:
            continue
        directive = directives[-1]
        if not directive.args or directive.args[0].lower() not in _LOG_LEVELS:
            unsupported.append(
                UnsupportedRateLimitEvidence(
                    reason="invalid-scalar",
                    directive_name=directive_name,
                    scope_id=scope.scope_id,
                    source=directive.source,
                )
            )
            return default, (f"invalid-{directive_name}",)
        return directive.args[0].lower(), ()
    return default, ()


def _parse_limit_req_usage(
    directive: DirectiveNode,
    *,
    declared_scope_id: str,
    effective_scope_id: str,
    origin: DestinationOrigin,
) -> EffectiveLimitReq | None:
    zone_name: str | None = None
    burst = 0
    delay: int | None = None
    nodelay = False
    for arg in directive.args:
        if arg.startswith("zone="):
            if zone_name is not None:
                return None
            zone_name = arg.removeprefix("zone=")
        elif arg.startswith("burst="):
            parsed = _parse_positive_or_zero_integer(arg.removeprefix("burst="))
            if parsed is None:
                return None
            burst = parsed
        elif arg.startswith("delay="):
            parsed = _parse_positive_or_zero_integer(arg.removeprefix("delay="))
            if parsed is None:
                return None
            delay = parsed
        elif arg == "nodelay":
            nodelay = True
        else:
            return None
    if zone_name is None:
        return None
    if nodelay and delay is not None:
        return None
    return EffectiveLimitReq(
        zone_name=zone_name,
        burst=burst,
        delay=delay,
        nodelay=nodelay,
        source=directive.source,
        declared_scope_id=declared_scope_id,
        effective_scope_id=effective_scope_id,
        origin=origin,
    )


def _parse_limit_conn_usage(
    directive: DirectiveNode,
    *,
    declared_scope_id: str,
    effective_scope_id: str,
    origin: DestinationOrigin,
) -> EffectiveLimitConn | None:
    if len(directive.args) != 2:
        return None
    parsed = _parse_positive_integer(directive.args[1])
    if parsed is None:
        return None
    return EffectiveLimitConn(
        zone_name=directive.args[0],
        connections=parsed,
        source=directive.source,
        declared_scope_id=declared_scope_id,
        effective_scope_id=effective_scope_id,
        origin=origin,
    )


def _directives_for_scope(
    scope_graph: NginxScopeGraph,
    scope_id: str,
    directive_name: str,
) -> tuple[DirectiveNode, ...]:
    return tuple(
        node
        for node in scope_graph.scope_nodes.get(scope_id, ())
        if isinstance(node, DirectiveNode) and node.name == directive_name
    )


def _record_illegal_directives(
    scope: NginxScope,
    scope_graph: NginxScopeGraph,
    directive_name: str,
    unsupported: list[UnsupportedRateLimitEvidence],
) -> None:
    for directive in _directives_for_scope(scope_graph, scope.scope_id, directive_name):
        unsupported.append(
            UnsupportedRateLimitEvidence(
                reason="illegal-context",
                directive_name=directive_name,
                scope_id=scope.scope_id,
                source=directive.source,
            )
        )


def _parse_positive_integer(value: str) -> int | None:
    try:
        parsed = int(value, 10)
    except ValueError:
        return None
    if parsed <= 0:
        return None
    return parsed


def _parse_positive_or_zero_integer(value: str) -> int | None:
    try:
        parsed = int(value, 10)
    except ValueError:
        return None
    if parsed < 0:
        return None
    return parsed


def _normalize_expression(value: str) -> str:
    return " ".join(value.strip().split())


__all__ = [
    "EffectiveLimitConn",
    "EffectiveLimitReq",
    "EffectiveRateLimitScope",
    "LimitConnZoneDefinition",
    "LimitReqZoneDefinition",
    "NginxRateLimitSemantics",
    "RequestRate",
    "UnsupportedRateLimitEvidence",
    "resolve_rate_limit_semantics",
]
