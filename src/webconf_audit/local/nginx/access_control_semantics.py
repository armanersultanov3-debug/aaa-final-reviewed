"""Effective Nginx route access-control semantics for policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Literal

from webconf_audit.local.nginx.effective_scope import NginxScopeGraph, NginxScopeKind
from webconf_audit.local.nginx.parser.ast import DirectiveNode, SourceSpan

AddressSubjectKind = Literal["all", "ip", "cidr", "unix", "hostname", "dynamic"]
AuthState = Literal["enabled", "off", "absent", "unknown"]
ProtectionClassification = Literal[
    "unconditionally_denied",
    "internal_only",
    "ip_restricted",
    "authenticated",
    "ip_and_auth",
    "ip_or_auth",
    "method_restricted_only",
    "unprotected",
    "indeterminate",
]


@dataclass(frozen=True)
class AddressAccessRule:
    action: Literal["allow", "deny"]
    subject_kind: AddressSubjectKind
    subject: str
    source: SourceSpan
    declared_scope_id: str


@dataclass(frozen=True)
class AuthControlState:
    state: AuthState
    source: SourceSpan | None
    declared_scope_id: str | None
    companion_source: SourceSpan | None = None
    companion_scope_id: str | None = None
    companion_present: bool | None = None
    incomplete_reason: str | None = None
    module_available: bool | None = None


@dataclass(frozen=True)
class MethodAccessControl:
    scope_id: str
    allowed_methods: tuple[str, ...]
    address_rules: tuple[AddressAccessRule, ...]
    auth_basic: AuthControlState
    auth_request: AuthControlState
    auth_jwt: AuthControlState
    auth_oidc: AuthControlState
    satisfy: Literal["all", "any"]
    complete: bool
    indeterminate_reasons: tuple[str, ...]
    classification: ProtectionClassification


@dataclass(frozen=True)
class EffectiveAccessControl:
    scope_id: str
    internal_only: bool
    unconditional_return: int | None
    address_rules: tuple[AddressAccessRule, ...]
    auth_basic: AuthControlState
    auth_request: AuthControlState
    auth_jwt: AuthControlState
    auth_oidc: AuthControlState
    satisfy: Literal["all", "any"]
    method_overrides: tuple[MethodAccessControl, ...]
    complete: bool
    indeterminate_reasons: tuple[str, ...]
    classification: ProtectionClassification


def resolve_effective_access_control(
    *,
    scope_graph: NginxScopeGraph,
    route_scope_id: str,
) -> EffectiveAccessControl:
    route_scope = scope_graph.scopes_by_id[route_scope_id]
    address_scope_id, address_rules = _nearest_address_rules(scope_graph, route_scope_id)
    auth_basic = _resolve_basic_auth(scope_graph, route_scope_id)
    auth_request = _resolve_auth_family(scope_graph, route_scope_id, directive_name="auth_request")
    auth_jwt = _resolve_optional_auth_family(scope_graph, route_scope_id, directive_name="auth_jwt")
    auth_oidc = _resolve_optional_auth_family(scope_graph, route_scope_id, directive_name="auth_oidc")
    satisfy = _resolve_satisfy(scope_graph, route_scope_id)
    internal_only = _has_internal(scope_graph, route_scope_id)
    unconditional_return = _unconditional_return_status(scope_graph, route_scope_id)
    reasons = set(route_scope.completeness_issues)
    reasons.update(_address_indeterminate_reasons(address_rules))
    if auth_basic.incomplete_reason is not None:
        reasons.add(auth_basic.incomplete_reason)
    if auth_jwt.state == "enabled":
        reasons.add("auth_jwt_module_availability_unknown")
    if auth_oidc.state == "enabled":
        reasons.add("auth_oidc_module_availability_unknown")
    complete = route_scope.complete and not route_scope.completeness_issues
    method_overrides = tuple(
        _resolve_method_override(scope_graph, scope_id)
        for scope_id in scope_graph.child_scope_ids.get(route_scope_id, ())
        if scope_graph.scopes_by_id[scope_id].kind == NginxScopeKind.LIMIT_EXCEPT
    )
    classification = _classify_control(
        address_rules=address_rules,
        auth_basic=auth_basic,
        auth_request=auth_request,
        auth_jwt=auth_jwt,
        auth_oidc=auth_oidc,
        satisfy=satisfy,
        internal_only=internal_only,
        unconditional_return=unconditional_return,
        method_overrides=method_overrides,
        indeterminate_reasons=tuple(sorted(reasons)),
    )
    return EffectiveAccessControl(
        scope_id=route_scope_id,
        internal_only=internal_only,
        unconditional_return=unconditional_return,
        address_rules=address_rules,
        auth_basic=auth_basic,
        auth_request=auth_request,
        auth_jwt=auth_jwt,
        auth_oidc=auth_oidc,
        satisfy=satisfy,
        method_overrides=method_overrides,
        complete=complete,
        indeterminate_reasons=tuple(sorted(reasons)),
        classification=classification,
    )


def _resolve_method_override(
    scope_graph: NginxScopeGraph,
    limit_except_scope_id: str,
) -> MethodAccessControl:
    scope = scope_graph.scopes_by_id[limit_except_scope_id]
    block = scope.block
    allowed_methods = tuple(block.args) if block is not None else ()
    address_scope_id, address_rules = _nearest_address_rules(
        scope_graph,
        limit_except_scope_id,
        include_limit_except=True,
    )
    auth_basic = _resolve_basic_auth(scope_graph, limit_except_scope_id, include_limit_except=True)
    auth_request = _resolve_auth_family(
        scope_graph,
        limit_except_scope_id,
        directive_name="auth_request",
        include_limit_except=True,
    )
    auth_jwt = _resolve_optional_auth_family(
        scope_graph,
        limit_except_scope_id,
        directive_name="auth_jwt",
        include_limit_except=True,
    )
    auth_oidc = _resolve_optional_auth_family(
        scope_graph,
        limit_except_scope_id,
        directive_name="auth_oidc",
        include_limit_except=True,
    )
    satisfy = _resolve_satisfy(scope_graph, limit_except_scope_id, include_limit_except=True)
    reasons = set(scope.completeness_issues)
    reasons.update(_address_indeterminate_reasons(address_rules))
    if auth_basic.incomplete_reason is not None:
        reasons.add(auth_basic.incomplete_reason)
    if auth_jwt.state == "enabled":
        reasons.add("auth_jwt_module_availability_unknown")
    if auth_oidc.state == "enabled":
        reasons.add("auth_oidc_module_availability_unknown")
    classification = _classify_control(
        address_rules=address_rules,
        auth_basic=auth_basic,
        auth_request=auth_request,
        auth_jwt=auth_jwt,
        auth_oidc=auth_oidc,
        satisfy=satisfy,
        internal_only=False,
        unconditional_return=None,
        method_overrides=(),
        indeterminate_reasons=tuple(sorted(reasons)),
    )
    return MethodAccessControl(
        scope_id=limit_except_scope_id,
        allowed_methods=allowed_methods,
        address_rules=address_rules,
        auth_basic=auth_basic,
        auth_request=auth_request,
        auth_jwt=auth_jwt,
        auth_oidc=auth_oidc,
        satisfy=satisfy,
        complete=scope.complete and not scope.completeness_issues,
        indeterminate_reasons=tuple(sorted(reasons)),
        classification=classification,
    )


def _nearest_address_rules(
    scope_graph: NginxScopeGraph,
    scope_id: str,
    *,
    include_limit_except: bool = False,
) -> tuple[str | None, tuple[AddressAccessRule, ...]]:
    allowed_scope_kinds = {
        NginxScopeKind.HTTP,
        NginxScopeKind.SERVER,
        NginxScopeKind.LOCATION,
    }
    if include_limit_except:
        allowed_scope_kinds.add(NginxScopeKind.LIMIT_EXCEPT)
    for scope in scope_graph.parent_chain(scope_id):
        if scope.kind not in allowed_scope_kinds:
            continue
        directives = [
            node
            for node in scope_graph.scope_nodes.get(scope.scope_id, ())
            if isinstance(node, DirectiveNode) and node.name in {"allow", "deny"} and node.args
        ]
        if directives:
            return scope.scope_id, tuple(_address_rule(scope.scope_id, directive) for directive in directives)
    return None, ()


def _address_rule(
    scope_id: str,
    directive: DirectiveNode,
) -> AddressAccessRule:
    subject = directive.args[0]
    return AddressAccessRule(
        action=directive.name,
        subject_kind=_address_subject_kind(subject),
        subject=subject,
        source=directive.source,
        declared_scope_id=scope_id,
    )


def _address_subject_kind(value: str) -> AddressSubjectKind:
    normalized = value.strip().lower()
    if "$" in normalized:
        return "dynamic"
    if normalized == "all":
        return "all"
    if normalized.startswith("unix:"):
        return "unix"
    try:
        if "/" in normalized:
            ipaddress.ip_network(normalized, strict=True)
            return "cidr"
        ipaddress.ip_address(normalized)
        return "ip"
    except ValueError:
        return "hostname"


def _resolve_basic_auth(
    scope_graph: NginxScopeGraph,
    scope_id: str,
    *,
    include_limit_except: bool = False,
) -> AuthControlState:
    state = _resolve_auth_family(
        scope_graph,
        scope_id,
        directive_name="auth_basic",
        include_limit_except=include_limit_except,
        off_token="off",
    )
    if state.state != "enabled":
        return state
    user_file = _nearest_directive(
        scope_graph,
        scope_id,
        directive_name="auth_basic_user_file",
        include_limit_except=include_limit_except,
    )
    if user_file is None:
        return AuthControlState(
            state="enabled",
            source=state.source,
            declared_scope_id=state.declared_scope_id,
            companion_present=False,
            incomplete_reason="missing_auth_basic_user_file",
        )
    return AuthControlState(
        state="enabled",
        source=state.source,
        declared_scope_id=state.declared_scope_id,
        companion_source=user_file[1].source,
        companion_scope_id=user_file[0],
        companion_present=True,
    )


def _resolve_optional_auth_family(
    scope_graph: NginxScopeGraph,
    scope_id: str,
    *,
    directive_name: str,
    include_limit_except: bool = False,
) -> AuthControlState:
    state = _resolve_auth_family(
        scope_graph,
        scope_id,
        directive_name=directive_name,
        include_limit_except=include_limit_except,
        off_token="off",
    )
    if state.state != "enabled":
        return state
    return AuthControlState(
        state="enabled",
        source=state.source,
        declared_scope_id=state.declared_scope_id,
        module_available=None,
    )


def _resolve_auth_family(
    scope_graph: NginxScopeGraph,
    scope_id: str,
    *,
    directive_name: str,
    include_limit_except: bool = False,
    off_token: str = "off",
) -> AuthControlState:
    directive = _nearest_directive(
        scope_graph,
        scope_id,
        directive_name=directive_name,
        include_limit_except=include_limit_except,
    )
    if directive is None:
        return AuthControlState(state="absent", source=None, declared_scope_id=None)
    declared_scope_id, node = directive
    value = node.args[0].strip().strip('"').strip("'").lower() if node.args else ""
    if value == off_token:
        return AuthControlState(
            state="off",
            source=node.source,
            declared_scope_id=declared_scope_id,
        )
    if not node.args:
        return AuthControlState(
            state="unknown",
            source=node.source,
            declared_scope_id=declared_scope_id,
        )
    return AuthControlState(
        state="enabled",
        source=node.source,
        declared_scope_id=declared_scope_id,
    )


def _nearest_directive(
    scope_graph: NginxScopeGraph,
    scope_id: str,
    *,
    directive_name: str,
    include_limit_except: bool = False,
) -> tuple[str, DirectiveNode] | None:
    allowed_scope_kinds = {
        NginxScopeKind.HTTP,
        NginxScopeKind.SERVER,
        NginxScopeKind.LOCATION,
    }
    if include_limit_except:
        allowed_scope_kinds.add(NginxScopeKind.LIMIT_EXCEPT)
    for scope in scope_graph.parent_chain(scope_id):
        if scope.kind not in allowed_scope_kinds:
            continue
        directives = [
            node
            for node in scope_graph.scope_nodes.get(scope.scope_id, ())
            if isinstance(node, DirectiveNode) and node.name == directive_name
        ]
        if directives:
            return scope.scope_id, directives[-1]
    return None


def _resolve_satisfy(
    scope_graph: NginxScopeGraph,
    scope_id: str,
    *,
    include_limit_except: bool = False,
) -> Literal["all", "any"]:
    directive = _nearest_directive(
        scope_graph,
        scope_id,
        directive_name="satisfy",
        include_limit_except=include_limit_except,
    )
    if directive is None:
        return "all"
    value = directive[1].args[0].strip().lower() if directive[1].args else ""
    return "any" if value == "any" else "all"


def _has_internal(
    scope_graph: NginxScopeGraph,
    scope_id: str,
) -> bool:
    for scope in scope_graph.parent_chain(scope_id):
        if scope.kind not in {NginxScopeKind.LOCATION, NginxScopeKind.LIMIT_EXCEPT}:
            continue
        if any(
            isinstance(node, DirectiveNode) and node.name == "internal"
            for node in scope_graph.scope_nodes.get(scope.scope_id, ())
        ):
            return True
    return False


def _unconditional_return_status(
    scope_graph: NginxScopeGraph,
    scope_id: str,
) -> int | None:
    for node in scope_graph.scope_nodes.get(scope_id, ()):
        if not isinstance(node, DirectiveNode) or node.name != "return" or not node.args:
            continue
        try:
            status_code = int(node.args[0])
        except ValueError:
            continue
        if status_code in {403, 404, 444}:
            return status_code
    return None


def _address_indeterminate_reasons(
    address_rules: tuple[AddressAccessRule, ...],
) -> tuple[str, ...]:
    reasons: set[str] = set()
    for rule in address_rules:
        if rule.subject_kind == "dynamic":
            reasons.add("dynamic-address-rule")
        if rule.subject_kind == "hostname":
            reasons.add("hostname-address-rule")
    return tuple(sorted(reasons))


def _classify_control(
    *,
    address_rules: tuple[AddressAccessRule, ...],
    auth_basic: AuthControlState,
    auth_request: AuthControlState,
    auth_jwt: AuthControlState,
    auth_oidc: AuthControlState,
    satisfy: Literal["all", "any"],
    internal_only: bool,
    unconditional_return: int | None,
    method_overrides: tuple[MethodAccessControl, ...],
    indeterminate_reasons: tuple[str, ...],
) -> ProtectionClassification:
    if unconditional_return in {403, 404, 444}:
        return "unconditionally_denied"
    if internal_only:
        return "internal_only"

    address_state = _evaluate_address_state(address_rules)
    enabled_auth = _enabled_authentication(auth_basic, auth_request)
    unknown_auth = _unknown_authentication(auth_basic, auth_request, auth_jwt, auth_oidc)

    if indeterminate_reasons and not address_state["unconditional_deny"]:
        if not enabled_auth and not address_state["ip_restricted"]:
            return "indeterminate"

    if address_state["unconditional_deny"] and satisfy == "any" and enabled_auth:
        return "authenticated"
    if address_state["unconditional_deny"]:
        return "unconditionally_denied"
    if satisfy == "any":
        if address_state["ip_restricted"] and enabled_auth:
            return "ip_or_auth"
        if address_state["ip_restricted"]:
            return "ip_restricted"
        if enabled_auth:
            return "authenticated"
        if unknown_auth:
            return "indeterminate"
    else:
        if address_state["ip_restricted"] and enabled_auth:
            return "ip_and_auth"
        if address_state["ip_restricted"]:
            return "ip_restricted"
        if enabled_auth:
            return "authenticated"
        if unknown_auth:
            return "indeterminate"

    if method_overrides:
        return "method_restricted_only"
    return "unprotected"


def _evaluate_address_state(
    address_rules: tuple[AddressAccessRule, ...],
) -> dict[str, bool]:
    if not address_rules:
        return {
            "unconditional_deny": False,
            "ip_restricted": False,
        }
    seen_restrictive_allow = False
    for rule in address_rules:
        if rule.action == "allow" and rule.subject_kind == "all":
            return {"unconditional_deny": False, "ip_restricted": False}
        if rule.action == "deny" and rule.subject_kind == "all":
            return {
                "unconditional_deny": not seen_restrictive_allow,
                "ip_restricted": seen_restrictive_allow,
            }
        if rule.action == "allow" and rule.subject_kind in {"ip", "cidr", "unix", "hostname", "dynamic"}:
            seen_restrictive_allow = True
    return {
        "unconditional_deny": False,
        "ip_restricted": False,
    }


def _enabled_authentication(
    auth_basic: AuthControlState,
    auth_request: AuthControlState,
) -> bool:
    basic_ok = auth_basic.state == "enabled" and auth_basic.companion_present is not False
    request_ok = auth_request.state == "enabled"
    return basic_ok or request_ok


def _unknown_authentication(
    auth_basic: AuthControlState,
    auth_request: AuthControlState,
    auth_jwt: AuthControlState,
    auth_oidc: AuthControlState,
) -> bool:
    return (
        (auth_basic.state == "enabled" and auth_basic.companion_present is False)
        or auth_request.state == "unknown"
        or auth_jwt.state == "enabled"
        or auth_oidc.state == "enabled"
    )


__all__ = [
    "AddressAccessRule",
    "AuthControlState",
    "EffectiveAccessControl",
    "MethodAccessControl",
    "resolve_effective_access_control",
]
