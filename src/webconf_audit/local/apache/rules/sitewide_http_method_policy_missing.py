from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    explicit_module_inventory,
    has_https_upstream_proxy,
    matching_location_scopes_for_path,
    nodes_guarantee_method_restriction,
)
from webconf_audit.local.apache.rules._redirect_scope_utils import (
    is_redirect_only_virtualhost,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.sitewide_http_method_policy_missing"
TITLE = "Apache request-scope method policy is missing"
DESCRIPTION = (
    "Apache config defines Location or proxy request routing but does not enforce "
    "a whole-scope HTTP method policy."
)
RECOMMENDATION = (
    "Define a whole-scope '<Location />' or equivalent request-scope method policy "
    "that allows only required methods such as GET, HEAD, POST, and OPTIONS."
)
_WHOLE_SCOPE_LOCATION_PATTERNS = frozenset(
    {"", "/", "^", "^/", "^/.*$", "^/.*", "^/(.*)$", "^/(.*)", "^.*$", "^(.*)$", "^(.*)", ".*"}
)
_REQUEST_POLICY_MARKERS = ("/admin", "/api", "/login", "/upload", "/uploads", "/")


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=370,
    tags=("access",),
)
def find_sitewide_http_method_policy_missing(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    modules = explicit_module_inventory(config_ast)
    findings: list[Finding] = []
    contexts = extract_virtualhost_contexts(config_ast)

    if not contexts:
        if _scope_requires_request_policy(config_ast.nodes, modules) and not _context_has_whole_scope_policy(
            config_ast,
            None,
            modules,
        ):
            findings.append(_finding_from_source(config_ast.nodes[0].source if config_ast.nodes else None))
        return findings

    for context in contexts:
        if context.optional_ancestor_names or is_redirect_only_virtualhost(context, modules):
            continue
        if not _scope_requires_request_policy(context.node.children, modules):
            continue
        if _context_has_whole_scope_policy(config_ast, context, modules):
            continue
        findings.append(_finding_from_source(context.node.source))

    return findings


def _scope_requires_request_policy(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> bool:
    return _has_any_location_block(nodes) or _has_any_proxy_routing(nodes, modules)


def _has_any_location_block(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> bool:
    for node in nodes:
        if not isinstance(node, ApacheBlockNode):
            continue
        if node.name.lower() in {"location", "locationmatch"} and _is_request_policy_location(node):
            return True
        if _has_any_location_block(node.children):
            return True
    return False


def _is_request_policy_location(block: ApacheBlockNode) -> bool:
    if not block.args:
        return False
    raw = " ".join(block.args).lower()
    if raw in _WHOLE_SCOPE_LOCATION_PATTERNS:
        return True
    return any(marker in raw for marker in _REQUEST_POLICY_MARKERS if marker != "/")


def _has_any_proxy_routing(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> bool:
    if has_https_upstream_proxy(nodes, modules):
        return True

    from webconf_audit.local.apache.rules._policy_semantics_utils import (  # noqa: PLC0415
        iter_enabled_scoped_directives,
    )

    return any(
        directive.name.lower() in {"proxypass", "proxypassmatch"}
        for directive in iter_enabled_scoped_directives(nodes, modules)
    )


def _context_has_whole_scope_policy(
    config_ast: ApacheConfigAst,
    context: ApacheVirtualHostContext | None,
    modules: frozenset[str],
) -> bool:
    for scope in matching_location_scopes_for_path(
        config_ast,
        "/",
        virtualhost_context=context,
    ):
        if not scope.args:
            continue
        raw = scope.args[0].strip().strip('"').strip("'")
        if raw not in _WHOLE_SCOPE_LOCATION_PATTERNS:
            continue
        if nodes_guarantee_method_restriction(scope.children, modules):
            return True
    return False


def _finding_from_source(source) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="low",
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path if source is not None else None,
            line=source.line if source is not None else None,
        ),
    )


__all__ = ["find_sitewide_http_method_policy_missing"]
