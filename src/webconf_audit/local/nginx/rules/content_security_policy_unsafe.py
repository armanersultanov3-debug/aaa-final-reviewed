"""nginx.content_security_policy_unsafe -- Content-Security-Policy is weak."""

from __future__ import annotations

from webconf_audit.csp_ast import CspDisposition, CspPolicy, parse_csp_header_value
from webconf_audit.local.nginx.effective_scope import NginxScopeKind, build_scope_graph
from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.response_header_semantics import resolve_response_header_semantics
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.content_security_policy_unsafe"

_UNSAFE_SCRIPT_TOKENS = {"'unsafe-inline'", "'unsafe-eval'"}


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy is weak",
    severity="low",
    description="Content-Security-Policy is present but lacks baseline protections.",
    recommendation=(
        "Include at least a restrictive default-src directive and avoid "
        "'unsafe-inline' / 'unsafe-eval' in script-src."
    ),
    category="local",
    server_type="nginx",
    tags=("headers",),
    order=254,
)
def find_content_security_policy_unsafe(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    scope_graph = build_scope_graph(config_ast)
    semantics = resolve_response_header_semantics(config_ast, scope_graph=scope_graph)
    seen_locations: set[tuple[str | None, int | None]] = set()

    for scope in scope_graph.scopes:
        if scope.kind not in {
            NginxScopeKind.SERVER,
            NginxScopeKind.LOCATION,
            NginxScopeKind.IF_IN_LOCATION,
        }:
            continue
        effective = semantics.effective_scopes_by_id.get(scope.scope_id)
        if effective is None:
            continue
        header_list = effective.base_headers
        if scope.kind == NginxScopeKind.IF_IN_LOCATION:
            parent_scope = scope_graph.scopes_by_id.get(scope.parent_id) if scope.parent_id is not None else None
            if parent_scope is None:
                continue
            parent_effective = semantics.effective_scopes_by_id.get(parent_scope.scope_id)
            if parent_effective is None:
                continue
            branch = next(
                (
                    branch
                    for branch in parent_effective.conditional_branches
                    if branch.branch_scope_id == scope.scope_id
                ),
                None,
            )
            header_list = branch.headers if branch is not None else ()
        csp_headers = [
            header
            for header in header_list
            if header.normalized_name == "content-security-policy"
            and bool(header.rendered_static_value.strip())
        ]
        if not csp_headers:
            continue
        if _policies_are_baseline_safe(csp_headers):
            continue
        location_key = (scope.source.file_path, scope.source.line)
        if location_key in seen_locations:
            continue
        seen_locations.add(location_key)
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Content-Security-Policy is weak",
                severity="low",
                description=(
                    "Content-Security-Policy is present but lacks a restrictive "
                    "default-src or safe script-src posture."
                ),
                recommendation=(
                    "Use a baseline such as default-src 'self'; form-action "
                    "'self'; and remove unsafe script tokens."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=scope.source.file_path,
                    line=scope.source.line,
                ),
            )
        )
    return findings


def _policies_are_baseline_safe(headers) -> bool:
    policies = [
        policy
        for header in headers
        for policy in parse_csp_header_value(
            header.rendered_static_value,
            disposition=CspDisposition.ENFORCE,
        ).policies
    ]
    if not policies:
        return True
    if _effective_unsafe_capability(policies, "'unsafe-inline'"):
        return False
    if _effective_unsafe_capability(policies, "'unsafe-eval'"):
        return False
    has_safe_default = any(_policy_has_safe_default_src(policy) for policy in policies)
    has_script_posture = all(policy.first_directive("script-src") is not None for policy in policies)
    return has_safe_default or has_script_posture


def _effective_unsafe_capability(policies: list[CspPolicy], token_name: str) -> bool:
    directives = [_script_directive(policy) for policy in policies]
    if not directives:
        return False
    return all(
        directive is not None
        and any(token.normalized == token_name for token in directive.tokens)
        for directive in directives
    )


def _policy_has_safe_default_src(policy: CspPolicy) -> bool:
    directive = policy.first_directive("default-src")
    if directive is None:
        return False
    tokens = {token.normalized for token in directive.tokens}
    if not tokens or "*" in tokens:
        return False
    return not bool(tokens & _UNSAFE_SCRIPT_TOKENS)


def _script_directive(policy: CspPolicy):
    return policy.first_directive("script-src") or policy.first_directive("default-src")


__all__ = ["find_content_security_policy_unsafe"]
