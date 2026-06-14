"""nginx.missing_content_security_policy -- Missing Content-Security-Policy header."""

from __future__ import annotations

from webconf_audit.local.nginx.effective_scope import NginxScopeKind, build_scope_graph
from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode
from webconf_audit.local.nginx.response_header_semantics import resolve_response_header_semantics
from webconf_audit.local.nginx.rules._scope_utils import skips_content_response_checks
from webconf_audit.local.nginx.rules._value_utils import iter_server_blocks_with_http_directives
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_content_security_policy"


@rule(
    rule_id=RULE_ID,
    title="Missing Content-Security-Policy header",
    severity="low",
    description="Server block does not define a Content-Security-Policy header.",
    recommendation="Add a Content-Security-Policy header to this server block.",
    category="local",
    server_type="nginx",
    tags=("headers",),
    order=214,
)
def find_missing_content_security_policy(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    scope_graph = build_scope_graph(config_ast)
    semantics = resolve_response_header_semantics(config_ast, scope_graph=scope_graph)

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header"},
    ):
        finding = _find_missing_content_security_policy_in_server(
            server_block,
            inherited_directives,
            scope_graph=scope_graph,
            semantics=semantics,
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _find_missing_content_security_policy_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
    *,
    scope_graph,
    semantics,
) -> Finding | None:
    del inherited_directives
    if skips_content_response_checks(server_block):
        return None

    server_scope = scope_graph.scope_for_block(server_block)
    missing_scope = _first_missing_enforcing_csp_scope(
        server_scope,
        scope_graph=scope_graph,
        semantics=semantics,
    )
    if missing_scope is None:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing Content-Security-Policy header",
        severity="low",
        description="Server block does not define a Content-Security-Policy header.",
        recommendation="Add a Content-Security-Policy header to this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=missing_scope.source.file_path,
            line=missing_scope.source.line,
        ),
    )


def _first_missing_enforcing_csp_scope(
    server_scope,
    *,
    scope_graph,
    semantics,
):
    candidate_scopes = (server_scope, *scope_graph.descendants(server_scope.scope_id))
    for scope in candidate_scopes:
        if scope.kind not in {
            NginxScopeKind.SERVER,
            NginxScopeKind.LOCATION,
            NginxScopeKind.IF_IN_LOCATION,
        }:
            continue
        effective = semantics.effective_scopes_by_id.get(scope.scope_id)
        if effective is None:
            continue
        header_list = (
            effective.base_headers
            if scope.kind != NginxScopeKind.IF_IN_LOCATION
            else ()
        )
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
        if any(
            header.normalized_name == "content-security-policy"
            and bool(header.rendered_static_value.strip())
            for header in header_list
        ):
            continue
        return scope
    return None


__all__ = ["find_missing_content_security_policy"]
