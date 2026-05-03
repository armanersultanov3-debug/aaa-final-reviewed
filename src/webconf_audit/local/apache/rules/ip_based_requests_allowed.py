from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ip_based_requests_allowed"
TITLE = "IP-based requests are not explicitly forbidden"
DESCRIPTION = (
    "Apache has a top-level ServerName but no server-context rewrite policy "
    "that forbids requests sent to an IP address instead of the expected host."
)
RECOMMENDATION = (
    "Enable mod_rewrite in the server context and add RewriteCond checks for "
    "the expected HTTP_HOST plus a RewriteRule that returns Forbidden for "
    "unexpected host/IP-based requests."
)
TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=363,
)
def find_ip_based_requests_allowed(config_ast: ApacheConfigAst) -> list[Finding]:
    directives = _iter_server_directives(config_ast.nodes)
    server_name = _top_level_server_name(directives)
    if server_name is None:
        return []
    if _has_ip_based_request_rewrite_policy(directives):
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title=TITLE,
            severity="low",
            description=(
                f"Apache server context for '{server_name.args[0]}' does not define a "
                "rewrite policy that forbids IP-based or unexpected Host requests."
            ),
            recommendation=RECOMMENDATION,
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=server_name.source.file_path,
                line=server_name.source.line,
            ),
        )
    ]


def _iter_server_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
            continue
        if node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
            directives.extend(_iter_server_directives(node.children))
    return directives


def _top_level_server_name(
    directives: list[ApacheDirectiveNode],
) -> ApacheDirectiveNode | None:
    for directive in directives:
        if directive.name.lower() == "servername" and directive.args:
            return directive
    return None


def _has_ip_based_request_rewrite_policy(
    directives: list[ApacheDirectiveNode],
) -> bool:
    return (
        _has_rewrite_engine_on(directives)
        and _has_http_host_condition(directives)
        and _has_request_uri_exception_condition(directives)
        and _has_forbidden_rewrite_rule(directives)
    )


def _has_rewrite_engine_on(directives: list[ApacheDirectiveNode]) -> bool:
    return any(
        directive.name.lower() == "rewriteengine"
        and bool(directive.args)
        and directive.args[0].lower() == "on"
        for directive in directives
    )


def _has_http_host_condition(directives: list[ApacheDirectiveNode]) -> bool:
    return any(
        directive.name.lower() == "rewritecond"
        and directive.args
        and directive.args[0].lower() == "%{http_host}"
        and any(arg.startswith("!") for arg in directive.args[1:])
        for directive in directives
    )


def _has_request_uri_exception_condition(
    directives: list[ApacheDirectiveNode],
) -> bool:
    return any(
        directive.name.lower() == "rewritecond"
        and directive.args
        and directive.args[0].lower() == "%{request_uri}"
        for directive in directives
    )


def _has_forbidden_rewrite_rule(directives: list[ApacheDirectiveNode]) -> bool:
    return any(
        directive.name.lower() == "rewriterule"
        and len(directive.args) >= 3
        and _rewrite_rule_forbids(directive.args[2:])
        for directive in directives
    )


def _rewrite_rule_forbids(args: list[str]) -> bool:
    for arg in args:
        normalized = arg.strip().strip("[]").lower()
        flags = [part.strip() for part in normalized.split(",")]
        if any(flag in {"f", "forbidden"} for flag in flags):
            return True
    return False


__all__ = ["find_ip_based_requests_allowed"]
