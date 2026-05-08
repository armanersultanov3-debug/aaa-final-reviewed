from __future__ import annotations

import re

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
_NGINX_VARIABLE_RE = re.compile(r"\$[A-Za-z0-9_]+")
_METHOD_ALLOWLIST_RE = re.compile(r"\^\((?P<methods>[A-Za-z|]+)\)\$", re.IGNORECASE)


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
    request_method_map_variables = _request_method_map_variables(config_ast)
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "server":
            continue
        if skips_content_response_checks(node):
            continue
        if not _server_requires_request_method_policy(node):
            continue
        if _server_has_sitewide_method_policy(node, request_method_map_variables):
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
    request_method_map_variables: set[str],
) -> bool:
    for location in server_block.children:
        if not isinstance(location, BlockNode) or location.name != "location":
            continue
        if not _is_root_location(location):
            continue
        if _location_has_approved_method_policy(location, request_method_map_variables):
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


def _location_has_approved_method_policy(
    location_block: BlockNode,
    request_method_map_variables: set[str],
) -> bool:
    for child in location_block.children:
        if not isinstance(child, BlockNode):
            continue
        if child.name == "limit_except" and _limit_except_is_approved(child):
            return True
        if child.name == "if" and _if_is_approved_method_allowlist(child):
            return True
        if child.name == "if" and _location_has_method_if_return(
            child,
            request_method_map_variables,
        ):
            return True
    return False


def _location_has_method_if_return(
    if_block: BlockNode,
    request_method_map_variables: set[str],
) -> bool:
    if not _if_returns_restrictive_code(if_block):
        return False
    referenced_variables = set(_NGINX_VARIABLE_RE.findall(_condition_text(if_block)))
    return bool(referenced_variables & request_method_map_variables)


def _if_is_approved_method_allowlist(if_block: BlockNode) -> bool:
    condition = _condition_text(if_block)
    if "$request_method" not in condition.lower():
        return False
    if "!~" not in condition:
        return False
    allowed_methods = _extract_allowed_methods_from_if_condition(condition)
    return allowed_methods == APPROVED_METHODS and _if_returns_restrictive_code(if_block)


def _if_returns_restrictive_code(if_block: BlockNode) -> bool:
    return any(
        isinstance(child, DirectiveNode)
        and child.name == "return"
        and child.args
        and child.args[0] in RESTRICTIVE_RETURN_CODES
        for child in if_block.children
    )


def _limit_except_is_approved(limit_except_block: BlockNode) -> bool:
    if not limit_except_block.args:
        return False
    normalized = {
        _normalize_method(method)
        for method in limit_except_block.args
        if _normalize_method(method)
    }
    return (
        bool(normalized)
        and normalized <= APPROVED_METHODS
        and _block_has_restrictive_action(limit_except_block)
    )


def _normalize_method(method: str) -> str:
    stripped = method.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        stripped = stripped[1:-1]
    return stripped.upper()


def _is_root_location(location_block: BlockNode) -> bool:
    return " ".join(location_block.args) in _ROOT_LOCATION_PATTERNS


def _request_method_map_variables(config_ast: ConfigAst) -> set[str]:
    return {
        _normalize_variable(node.args[1])
        for node in iter_nodes(config_ast.nodes)
        if isinstance(node, BlockNode)
        and node.name == "map"
        and len(node.args) >= 2
        and _normalize_variable(node.args[0]) == "$request_method"
        and _normalize_variable(node.args[1])
    }


def _condition_text(if_block: BlockNode) -> str:
    return " ".join(if_block.args).strip()


def _extract_allowed_methods_from_if_condition(condition: str) -> frozenset[str] | None:
    normalized = condition.strip()
    if normalized.startswith("(") and normalized.endswith(")"):
        normalized = normalized[1:-1].strip()

    for operator in ("!~*", "!~"):
        if operator not in normalized:
            continue
        _, pattern = normalized.split(operator, maxsplit=1)
        pattern = _strip_matching_quotes(pattern.strip())
        match = _METHOD_ALLOWLIST_RE.fullmatch(pattern)
        if match is None:
            return None
        return frozenset(
            _normalize_method(method)
            for method in match.group("methods").split("|")
            if _normalize_method(method)
        )
    return None


def _strip_matching_quotes(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        return stripped[1:-1]
    return stripped


def _block_has_restrictive_action(block: BlockNode) -> bool:
    return any(
        isinstance(child, DirectiveNode) and child.name == "deny" and child.args == ["all"]
        for child in block.children
    ) or any(
        isinstance(child, DirectiveNode)
        and child.name == "return"
        and child.args
        and child.args[0] in RESTRICTIVE_RETURN_CODES
        for child in block.children
    )


def _normalize_variable(value: str) -> str:
    return _strip_matching_quotes(value).lower()


__all__ = ["find_sitewide_http_method_policy_missing"]
