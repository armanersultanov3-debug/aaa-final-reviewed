"""Bounded Nginx location matching for policy-backed route evidence."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal
from urllib.parse import unquote, urlsplit

from webconf_audit.local.nginx.effective_scope import NginxScope, NginxScopeGraph, NginxScopeKind
from webconf_audit.local.nginx.parser.ast import DirectiveNode
from webconf_audit.policy_models import NginxLocationSelector

LocationMatchStatus = Literal["selected", "unmatched", "ambiguous", "indeterminate"]


@dataclass(frozen=True)
class DeclaredLocationBinding:
    status: LocationMatchStatus
    selector: NginxLocationSelector
    matched_scopes: tuple[NginxScope, ...]
    indeterminate_reasons: tuple[str, ...]

    @property
    def selected_scope(self) -> NginxScope | None:
        if len(self.matched_scopes) == 1:
            return self.matched_scopes[0]
        return None


@dataclass(frozen=True)
class ResolvedLocationSample:
    status: LocationMatchStatus
    sample_uri: str
    normalized_uri: str | None
    server_scope_id: str
    selected_scope_id: str | None
    selected_scope: NginxScope | None
    indeterminate_reasons: tuple[str, ...]


@dataclass(frozen=True)
class _ParsedLocation:
    scope: NginxScope
    modifier: Literal["exact", "prefix", "prefix_no_regex", "regex", "regex_i", "named"]
    pattern: str


def bind_declared_location(
    *,
    scope_graph: NginxScopeGraph,
    server_scope_id: str,
    selector: NginxLocationSelector,
) -> DeclaredLocationBinding:
    matched = tuple(
        scope
        for scope in _server_location_scopes(scope_graph, server_scope_id)
        if _scope_matches_selector(scope, selector)
    )
    if not matched:
        return DeclaredLocationBinding(
            status="unmatched",
            selector=selector,
            matched_scopes=(),
            indeterminate_reasons=(),
        )
    if len(matched) > 1:
        return DeclaredLocationBinding(
            status="ambiguous",
            selector=selector,
            matched_scopes=matched,
            indeterminate_reasons=("multiple-declared-location-matches",),
        )
    return DeclaredLocationBinding(
        status="selected",
        selector=selector,
        matched_scopes=matched,
        indeterminate_reasons=(),
    )


def resolve_location_sample(
    *,
    scope_graph: NginxScopeGraph,
    server_scope_id: str,
    sample_uri: str,
) -> ResolvedLocationSample:
    try:
        merge_slashes = _effective_merge_slashes(scope_graph, server_scope_id)
        normalized_uri = _normalize_sample_uri(sample_uri, merge_slashes=merge_slashes)
    except ValueError as exc:
        return ResolvedLocationSample(
            status="indeterminate",
            sample_uri=sample_uri,
            normalized_uri=None,
            server_scope_id=server_scope_id,
            selected_scope_id=None,
            selected_scope=None,
            indeterminate_reasons=(str(exc),),
        )

    selected, reasons = _select_in_parent(
        scope_graph=scope_graph,
        parent_scope_id=server_scope_id,
        normalized_uri=normalized_uri,
    )
    if reasons:
        return ResolvedLocationSample(
            status="indeterminate",
            sample_uri=sample_uri,
            normalized_uri=normalized_uri,
            server_scope_id=server_scope_id,
            selected_scope_id=None,
            selected_scope=None,
            indeterminate_reasons=reasons,
        )
    selected_scope = selected or scope_graph.scopes_by_id[server_scope_id]
    return ResolvedLocationSample(
        status="selected",
        sample_uri=sample_uri,
        normalized_uri=normalized_uri,
        server_scope_id=server_scope_id,
        selected_scope_id=selected_scope.scope_id,
        selected_scope=selected_scope,
        indeterminate_reasons=(),
    )


def _select_in_parent(
    *,
    scope_graph: NginxScopeGraph,
    parent_scope_id: str,
    normalized_uri: str,
) -> tuple[NginxScope | None, tuple[str, ...]]:
    candidates = [
        _parse_location_scope(scope)
        for scope in _direct_child_locations(scope_graph, parent_scope_id)
    ]
    exact_matches = [
        candidate
        for candidate in candidates
        if candidate.modifier == "exact" and candidate.pattern == normalized_uri
    ]
    if exact_matches:
        if len(exact_matches) > 1:
            return None, ("multiple-exact-location-matches",)
        return exact_matches[0].scope, ()

    prefix_matches = [
        candidate
        for candidate in candidates
        if candidate.modifier in {"prefix", "prefix_no_regex"}
        and normalized_uri.startswith(candidate.pattern)
    ]
    longest_prefix = max(prefix_matches, key=lambda candidate: len(candidate.pattern), default=None)

    if longest_prefix is not None and longest_prefix.modifier == "prefix_no_regex":
        nested, reasons = _select_nested(
            scope_graph=scope_graph,
            selected_scope=longest_prefix.scope,
            normalized_uri=normalized_uri,
        )
        return nested or longest_prefix.scope, reasons

    for candidate in candidates:
        if candidate.modifier not in {"regex", "regex_i"}:
            continue
        compiled = _compile_runtime_regex(candidate.pattern, case_insensitive=candidate.modifier == "regex_i")
        if compiled is None:
            return None, ("unsupported-regex-location",)
        if compiled.search(normalized_uri):
            nested, reasons = _select_nested(
                scope_graph=scope_graph,
                selected_scope=candidate.scope,
                normalized_uri=normalized_uri,
            )
            return nested or candidate.scope, reasons

    if longest_prefix is None:
        return None, ()
    nested, reasons = _select_nested(
        scope_graph=scope_graph,
        selected_scope=longest_prefix.scope,
        normalized_uri=normalized_uri,
    )
    return nested or longest_prefix.scope, reasons


def _select_nested(
    *,
    scope_graph: NginxScopeGraph,
    selected_scope: NginxScope,
    normalized_uri: str,
) -> tuple[NginxScope | None, tuple[str, ...]]:
    nested_locations = _direct_child_locations(scope_graph, selected_scope.scope_id)
    if not nested_locations:
        return None, ()
    return _select_in_parent(
        scope_graph=scope_graph,
        parent_scope_id=selected_scope.scope_id,
        normalized_uri=normalized_uri,
    )


def _direct_child_locations(
    scope_graph: NginxScopeGraph,
    parent_scope_id: str,
) -> tuple[NginxScope, ...]:
    return tuple(
        scope_graph.scopes_by_id[scope_id]
        for scope_id in scope_graph.child_scope_ids.get(parent_scope_id, ())
        if scope_graph.scopes_by_id[scope_id].kind == NginxScopeKind.LOCATION
    )


def _server_location_scopes(
    scope_graph: NginxScopeGraph,
    server_scope_id: str,
) -> tuple[NginxScope, ...]:
    return tuple(
        scope
        for scope in scope_graph.descendants(server_scope_id)
        if scope.kind == NginxScopeKind.LOCATION
    )


def _scope_matches_selector(scope: NginxScope, selector: NginxLocationSelector) -> bool:
    parsed = _parse_location_scope(scope)
    if parsed.modifier != selector.modifier:
        return False
    if parsed.pattern != selector.pattern:
        return False
    if selector.source_path is None:
        return True
    return scope.source.file_path == selector.source_path


def _parse_location_scope(scope: NginxScope) -> _ParsedLocation:
    block = scope.block
    if block is None or block.name != "location":
        raise ValueError(f"Scope {scope.scope_id!r} is not a location block.")
    if not block.args:
        return _ParsedLocation(scope=scope, modifier="prefix", pattern="/")
    first = block.args[0]
    if first == "=" and len(block.args) > 1:
        return _ParsedLocation(scope=scope, modifier="exact", pattern=block.args[1])
    if first == "^~" and len(block.args) > 1:
        return _ParsedLocation(scope=scope, modifier="prefix_no_regex", pattern=block.args[1])
    if first == "~":
        return _ParsedLocation(scope=scope, modifier="regex", pattern=" ".join(block.args[1:]))
    if first == "~*":
        return _ParsedLocation(scope=scope, modifier="regex_i", pattern=" ".join(block.args[1:]))
    if first.startswith("@"):
        return _ParsedLocation(scope=scope, modifier="named", pattern=first)
    return _ParsedLocation(scope=scope, modifier="prefix", pattern=first)


def _effective_merge_slashes(
    scope_graph: NginxScopeGraph,
    server_scope_id: str,
) -> bool:
    for scope in scope_graph.parent_chain(server_scope_id):
        directives = [
            node
            for node in scope_graph.scope_nodes.get(scope.scope_id, ())
            if isinstance(node, DirectiveNode) and node.name == "merge_slashes" and node.args
        ]
        if directives:
            return directives[-1].args[0].lower() != "off"
    return True


def _normalize_sample_uri(
    value: str,
    *,
    merge_slashes: bool,
) -> str:
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or parts.query or parts.fragment:
        raise ValueError("invalid-sample-uri")
    if not value.startswith("/"):
        raise ValueError("invalid-sample-uri")
    decoded = unquote(value)
    trailing_slash = decoded.endswith("/")
    normalized_parts: list[str] = []
    for index, part in enumerate(decoded.split("/")):
        if index == 0:
            continue
        if part == ".":
            continue
        if part == "..":
            if normalized_parts:
                normalized_parts.pop()
            continue
        if merge_slashes and part == "":
            continue
        normalized_parts.append(part)
    normalized = "/" + "/".join(normalized_parts)
    if trailing_slash and normalized != "/":
        normalized += "/"
    if merge_slashes:
        normalized = re.sub(r"/{2,}", "/", normalized)
    return normalized or "/"


def _compile_runtime_regex(
    pattern: str,
    *,
    case_insensitive: bool,
):
    if "(?<" in pattern or "\\K" in pattern or "(?>" in pattern or "(?R" in pattern or "(?0" in pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE if case_insensitive else 0)
    except re.error:
        return None


__all__ = [
    "DeclaredLocationBinding",
    "ResolvedLocationSample",
    "bind_declared_location",
    "resolve_location_sample",
]
