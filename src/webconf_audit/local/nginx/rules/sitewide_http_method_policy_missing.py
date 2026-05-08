from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.local.nginx.rules._scope_utils import skips_content_response_checks
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cwe, owasp_top10_2021

RULE_ID = "nginx.sitewide_http_method_policy_missing"
TITLE = "Site-wide HTTP method policy is missing"
DESCRIPTION = (
    "Nginx exposes request-scope handling but does not enforce a whole-scope HTTP "
    "method policy."
)
RECOMMENDATION = (
    "Define a root or equivalent request-scope policy that allows only required "
    "methods such as GET, HEAD, POST, and OPTIONS, using limit_except or a "
    "request-method if/map/return pattern."
)
APPROVED_METHODS = frozenset({"GET", "HEAD", "POST", "OPTIONS"})
RESTRICTIVE_RETURN_CODES = frozenset({"403", "405", "444"})
_ROOT_LOCATION_PATTERNS = frozenset({"/", "^~ /"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    standards=(
        cwe(650),
        owasp_top10_2021("A05:2021"),
    ),
    order=221,
    tags=("access",),
)
def find_sitewide_http_method_policy_missing(config_ast: ConfigAst) -> list[Finding]:
    request_method_map_present = _has_request_method_map(config_ast)
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "server":
            continue
        if skips_content_response_checks(node):
            continue
        if not _server_requires_request_method_policy(node):
            continue
        if _server_has_sitewide_method_policy(node, request_method_map_present):
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=DESCRIPTION,
                recommendation=RECOMMENDATION,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
            )
        )

    return findings


def _server_requires_request_method_policy(server_block: BlockNode) -> bool:
    return any(
        isinstance(location, BlockNode)
        and location.name == "location"
        and _is_root_location(location)
        and _location_exposes_request_scope(location)
        for location in server_block.children
    )


def _server_has_sitewide_method_policy(
    server_block: BlockNode,
    request_method_map_present: bool,
) -> bool:
    for location in server_block.children:
        if not isinstance(location, BlockNode) or location.name != "location":
            continue
        if not _is_root_location(location):
            continue
        if _location_has_approved_method_policy(location):
            return True
        if request_method_map_present and _location_has_method_if_return(location):
            return True
    return False


def _location_exposes_request_scope(location_block: BlockNode) -> bool:
    return any(
        isinstance(child, DirectiveNode)
        and child.name in {"proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass", "memcached_pass"}
        for child in location_block.children
    ) or any(
        isinstance(child, BlockNode)
        and child.name in {"if", "limit_except"}
        for child in location_block.children
    )


def _location_has_approved_method_policy(location_block: BlockNode) -> bool:
    for child in location_block.children:
        if not isinstance(child, BlockNode):
            continue
        if child.name == "limit_except" and _limit_except_is_approved(child.args):
            return True
        if child.name == "if" and _if_is_approved_method_allowlist(child):
            return True
    return False


def _location_has_method_if_return(location_block: BlockNode) -> bool:
    return any(
        isinstance(child, BlockNode)
        and child.name == "if"
        and _if_returns_restrictive_code(child)
        for child in location_block.children
    )


def _if_is_approved_method_allowlist(if_block: BlockNode) -> bool:
    condition = " ".join(if_block.args).lower()
    if "$request_method" not in condition:
        return False
    if "!~" not in condition:
        return False
    return all(method.lower() in condition for method in APPROVED_METHODS) and _if_returns_restrictive_code(
        if_block
    )


def _if_returns_restrictive_code(if_block: BlockNode) -> bool:
    return any(
        isinstance(child, DirectiveNode)
        and child.name == "return"
        and child.args
        and child.args[0] in RESTRICTIVE_RETURN_CODES
        for child in if_block.children
    )


def _limit_except_is_approved(methods: list[str]) -> bool:
    if not methods:
        return False
    normalized = {_normalize_method(method) for method in methods if _normalize_method(method)}
    return bool(normalized) and normalized <= APPROVED_METHODS


def _normalize_method(method: str) -> str:
    stripped = method.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        stripped = stripped[1:-1]
    return stripped.upper()


def _is_root_location(location_block: BlockNode) -> bool:
    return " ".join(location_block.args) in _ROOT_LOCATION_PATTERNS


def _has_request_method_map(config_ast: ConfigAst) -> bool:
    return any(
        isinstance(node, BlockNode)
        and node.name == "map"
        and node.args
        and node.args[0].strip().strip('"').strip("'").lower() == "$request_method"
        for node in iter_nodes(config_ast.nodes)
    )


__all__ = ["find_sitewide_http_method_policy_missing"]
