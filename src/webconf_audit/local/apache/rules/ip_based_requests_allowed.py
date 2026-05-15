"""Implements rule ``apache.ip_based_requests_allowed``.

Location: ``src/webconf_audit/local/apache/rules/ip_based_requests_allowed.py``.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    explicit_module_inventory,
    iter_enabled_directives,
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
    modules = explicit_module_inventory(config_ast)
    directives = _iter_server_directives(config_ast.nodes, modules)
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
    modules: frozenset[str],
) -> list[ApacheDirectiveNode]:
    return iter_enabled_directives(nodes, modules)


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
    for index, directive in enumerate(directives):
        if not _is_forbidden_rewrite_rule(directive):
            continue
        if not _rewrite_engine_enabled_before(directives, index):
            continue
        conditions = _rewrite_conditions_for_rule(directives, index)
        if len(conditions) < 2:
            continue
        if not _is_request_uri_exception_condition(conditions[-1]):
            continue
        if any(_is_http_host_condition(condition) for condition in conditions[:-1]):
            return True
    return False


def _rewrite_engine_enabled_before(
    directives: list[ApacheDirectiveNode],
    rule_index: int,
) -> bool:
    enabled = False
    for directive in directives[:rule_index]:
        if directive.name.lower() != "rewriteengine" or not directive.args:
            continue
        enabled = directive.args[0].lower() == "on"
    return enabled


def _rewrite_conditions_for_rule(
    directives: list[ApacheDirectiveNode],
    rule_index: int,
) -> list[ApacheDirectiveNode]:
    conditions: list[ApacheDirectiveNode] = []
    index = rule_index - 1
    while index >= 0 and directives[index].name.lower() == "rewritecond":
        conditions.append(directives[index])
        index -= 1
    conditions.reverse()
    return conditions


def _is_http_host_condition(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.args
        and directive.args[0].lower() == "%{http_host}"
        and any(arg.startswith("!") for arg in directive.args[1:])
    )


def _is_request_uri_exception_condition(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.args
        and directive.args[0].lower() == "%{request_uri}"
        and any(arg.startswith("!") for arg in directive.args[1:])
    )


def _is_forbidden_rewrite_rule(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "rewriterule"
        and len(directive.args) >= 3
        and _rewrite_rule_forbids(directive.args[2:])
    )


def _rewrite_rule_forbids(args: list[str]) -> bool:
    for arg in args:
        normalized = arg.strip().strip("[]").lower()
        flags = [part.strip() for part in normalized.split(",")]
        if any(flag in {"f", "forbidden"} for flag in flags):
            return True
    return False


__all__ = ["find_ip_based_requests_allowed"]
