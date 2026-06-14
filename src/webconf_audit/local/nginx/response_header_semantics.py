"""Reusable Nginx response-header semantics."""

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

HeaderInheritanceMode = Literal["on", "off", "merge"]
ConditionKind = Literal["unconditional", "constant_true", "constant_false", "dynamic"]

_ALLOWED_SCOPE_KINDS = frozenset(
    {
        NginxScopeKind.HTTP,
        NginxScopeKind.SERVER,
        NginxScopeKind.LOCATION,
        NginxScopeKind.IF_IN_LOCATION,
    }
)
_ADD_HEADER_INHERIT_MODES = frozenset({"on", "off", "merge"})
_DEFAULT_HEADER_STATUSES = frozenset({200, 201, 204, 206, 301, 302, 303, 304, 307, 308})
_NGINX_VARIABLE_RE = re.compile(r"\$(?:\{(?P<braced>[A-Za-z0-9_]+)\}|(?P<plain>[A-Za-z0-9_]+))")


@dataclass(frozen=True, slots=True)
class HeaderApplicability:
    all_statuses: bool
    known_statuses: frozenset[int]
    conditional_branch_id: str | None


@dataclass(frozen=True, slots=True)
class EffectiveResponseHeader:
    normalized_name: str
    configured_name: str
    raw_value_tokens: tuple[str, ...]
    rendered_static_value: str
    always: bool
    source: SourceSpan
    declared_scope_id: str
    effective_scope_id: str
    origin: Literal["explicit", "inherited", "merged"]
    dynamic_variables: tuple[str, ...]
    applicability: HeaderApplicability


@dataclass(frozen=True, slots=True)
class EffectiveResponseBranch:
    branch_scope_id: str
    parent_scope_id: str
    condition: str | None
    condition_kind: ConditionKind
    headers: tuple[EffectiveResponseHeader, ...]
    complete: bool
    indeterminate_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EffectiveResponseScope:
    scope_id: str
    base_headers: tuple[EffectiveResponseHeader, ...]
    conditional_branches: tuple[EffectiveResponseBranch, ...]
    inherit_mode: HeaderInheritanceMode
    complete: bool
    indeterminate_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UnsupportedResponseHeaderEvidence:
    reason: str
    directive_name: str
    scope_id: str
    source: SourceSpan
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class NginxResponseHeaderSemantics:
    scope_graph: NginxScopeGraph
    effective_scopes: tuple[EffectiveResponseScope, ...]
    effective_scopes_by_id: dict[str, EffectiveResponseScope]
    unsupported_evidence: tuple[UnsupportedResponseHeaderEvidence, ...]


def resolve_response_header_semantics(
    config_ast: ConfigAst,
    *,
    scope_graph: NginxScopeGraph,
) -> NginxResponseHeaderSemantics:
    del config_ast
    unsupported: list[UnsupportedResponseHeaderEvidence] = []
    local_headers_by_scope: dict[str, tuple[DirectiveNode, ...]] = {}
    local_inherit_modes: dict[str, HeaderInheritanceMode] = {}

    for scope in scope_graph.scopes:
        directives = tuple(
            node
            for node in scope_graph.scope_nodes.get(scope.scope_id, ())
            if isinstance(node, DirectiveNode)
        )
        add_headers = tuple(node for node in directives if node.name == "add_header")
        add_header_inherit = tuple(node for node in directives if node.name == "add_header_inherit")
        if add_headers:
            if scope.kind in _ALLOWED_SCOPE_KINDS:
                local_headers_by_scope[scope.scope_id] = add_headers
            else:
                unsupported.extend(
                    UnsupportedResponseHeaderEvidence(
                        reason="illegal-context",
                        directive_name="add_header",
                        scope_id=scope.scope_id,
                        source=directive.source,
                    )
                    for directive in add_headers
                )
        if add_header_inherit:
            if scope.kind not in _ALLOWED_SCOPE_KINDS:
                unsupported.extend(
                    UnsupportedResponseHeaderEvidence(
                        reason="illegal-context",
                        directive_name="add_header_inherit",
                        scope_id=scope.scope_id,
                        source=directive.source,
                    )
                    for directive in add_header_inherit
                )
                continue
            local_inherit_modes[scope.scope_id] = _last_inherit_mode(add_header_inherit, default="on")

    resolved_headers: dict[str, tuple[EffectiveResponseHeader, ...]] = {}
    resolved_modes: dict[str, HeaderInheritanceMode] = {}
    effective_lookup: dict[str, EffectiveResponseScope] = {}

    for scope in scope_graph.scopes:
        parent_headers = resolved_headers.get(scope.parent_id, ())
        parent_mode = resolved_modes.get(scope.parent_id, "on")
        inherit_mode = local_inherit_modes.get(scope.scope_id, parent_mode)
        local_directives = local_headers_by_scope.get(scope.scope_id, ())
        base_headers = _effective_headers_for_scope(
            scope_id=scope.scope_id,
            local_directives=local_directives,
            inherited_headers=parent_headers,
            inherit_mode=inherit_mode,
        )
        resolved_headers[scope.scope_id] = base_headers
        resolved_modes[scope.scope_id] = inherit_mode
    for scope in scope_graph.scopes:
        branches = tuple(
            _branch_payload(
                scope_graph.scopes_by_id[child_scope_id],
                headers=resolved_headers.get(child_scope_id, ()),
            )
            for child_scope_id in scope_graph.child_scope_ids.get(scope.scope_id, ())
            if scope_graph.scopes_by_id[child_scope_id].kind == NginxScopeKind.IF_IN_LOCATION
        )
        effective_lookup[scope.scope_id] = EffectiveResponseScope(
            scope_id=scope.scope_id,
            base_headers=resolved_headers.get(scope.scope_id, ()),
            conditional_branches=branches,
            inherit_mode=resolved_modes.get(scope.scope_id, "on"),
            complete=scope.complete,
            indeterminate_reasons=scope.completeness_issues,
        )

    effective_scopes = tuple(
        effective_lookup[scope.scope_id]
        for scope in scope_graph.scopes
    )
    return NginxResponseHeaderSemantics(
        scope_graph=scope_graph,
        effective_scopes=effective_scopes,
        effective_scopes_by_id=effective_lookup,
        unsupported_evidence=tuple(unsupported),
    )


def _effective_headers_for_scope(
    *,
    scope_id: str,
    local_directives: tuple[DirectiveNode, ...],
    inherited_headers: tuple[EffectiveResponseHeader, ...],
    inherit_mode: HeaderInheritanceMode,
) -> tuple[EffectiveResponseHeader, ...]:
    local_headers = tuple(
        _explicit_header(directive, scope_id=scope_id)
        for directive in local_directives
    )
    if inherit_mode == "off":
        return local_headers
    if inherit_mode == "merge":
        return local_headers + tuple(
            _inherited_header(header, scope_id=scope_id, origin="merged")
            for header in inherited_headers
        )
    if local_headers:
        return local_headers
    return tuple(
        _inherited_header(header, scope_id=scope_id, origin="inherited")
        for header in inherited_headers
    )


def _explicit_header(
    directive: DirectiveNode,
    *,
    scope_id: str,
) -> EffectiveResponseHeader:
    configured_name = directive.args[0] if directive.args else ""
    value_tokens, always = _header_value_tokens(directive.args)
    rendered_value = _rendered_static_value(value_tokens)
    return EffectiveResponseHeader(
        normalized_name=configured_name.lower(),
        configured_name=configured_name,
        raw_value_tokens=tuple(value_tokens),
        rendered_static_value=rendered_value,
        always=always,
        source=directive.source,
        declared_scope_id=scope_id,
        effective_scope_id=scope_id,
        origin="explicit",
        dynamic_variables=_extract_variables(rendered_value),
        applicability=_applicability(always=always, conditional_branch_id=None),
    )


def _inherited_header(
    header: EffectiveResponseHeader,
    *,
    scope_id: str,
    origin: Literal["inherited", "merged"],
) -> EffectiveResponseHeader:
    applicability = HeaderApplicability(
        all_statuses=header.applicability.all_statuses,
        known_statuses=header.applicability.known_statuses,
        conditional_branch_id=header.applicability.conditional_branch_id,
    )
    return EffectiveResponseHeader(
        normalized_name=header.normalized_name,
        configured_name=header.configured_name,
        raw_value_tokens=header.raw_value_tokens,
        rendered_static_value=header.rendered_static_value,
        always=header.always,
        source=header.source,
        declared_scope_id=header.declared_scope_id,
        effective_scope_id=scope_id,
        origin=origin,
        dynamic_variables=header.dynamic_variables,
        applicability=applicability,
    )


def _branch_payload(
    branch_scope: NginxScope,
    *,
    headers: tuple[EffectiveResponseHeader, ...],
) -> EffectiveResponseBranch:
    condition = " ".join(branch_scope.block.args).strip() if branch_scope.block is not None else None
    branch_headers = tuple(
        EffectiveResponseHeader(
            normalized_name=header.normalized_name,
            configured_name=header.configured_name,
            raw_value_tokens=header.raw_value_tokens,
            rendered_static_value=header.rendered_static_value,
            always=header.always,
            source=header.source,
            declared_scope_id=header.declared_scope_id,
            effective_scope_id=header.effective_scope_id,
            origin=header.origin,
            dynamic_variables=header.dynamic_variables,
            applicability=_applicability(always=header.always, conditional_branch_id=branch_scope.scope_id),
        )
        for header in headers
    )
    return EffectiveResponseBranch(
        branch_scope_id=branch_scope.scope_id,
        parent_scope_id=branch_scope.parent_id or branch_scope.scope_id,
        condition=condition,
        condition_kind=_classify_condition(condition),
        headers=branch_headers,
        complete=branch_scope.complete,
        indeterminate_reasons=branch_scope.completeness_issues,
    )


def _applicability(
    *,
    always: bool,
    conditional_branch_id: str | None,
) -> HeaderApplicability:
    return HeaderApplicability(
        all_statuses=always,
        known_statuses=frozenset() if always else _DEFAULT_HEADER_STATUSES,
        conditional_branch_id=conditional_branch_id,
    )


def _header_value_tokens(args: list[str]) -> tuple[list[str], bool]:
    if len(args) >= 3 and args[-1].lower() == "always":
        return args[1:-1], True
    return args[1:], False


def _rendered_static_value(tokens: list[str]) -> str:
    value = " ".join(tokens).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


def _extract_variables(value: str) -> tuple[str, ...]:
    return tuple(
        f"${match.group('braced') or match.group('plain')}"
        for match in _NGINX_VARIABLE_RE.finditer(value)
    )


def _last_inherit_mode(
    directives: tuple[DirectiveNode, ...],
    *,
    default: HeaderInheritanceMode,
) -> HeaderInheritanceMode:
    for directive in reversed(directives):
        if not directive.args:
            continue
        mode = directive.args[0].lower()
        if mode in _ADD_HEADER_INHERIT_MODES:
            return mode  # type: ignore[return-value]
    return default


def _classify_condition(condition: str | None) -> ConditionKind:
    if condition is None:
        return "unconditional"
    stripped = condition.strip()
    if stripped in {"", "0"}:
        return "constant_false"
    if "$" in stripped:
        return "dynamic"
    return "constant_true"


__all__ = [
    "ConditionKind",
    "EffectiveResponseBranch",
    "EffectiveResponseHeader",
    "EffectiveResponseScope",
    "HeaderApplicability",
    "NginxResponseHeaderSemantics",
    "UnsupportedResponseHeaderEvidence",
    "resolve_response_header_semantics",
]
