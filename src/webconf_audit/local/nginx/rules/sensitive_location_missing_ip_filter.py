from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.sensitive_location_missing_ip_filter"
TITLE = "Sensitive location lacks an IP allow/deny filter"
DESCRIPTION = (
    "Sensitive location has an access restriction, but does not define a "
    "restrictive allow/deny IP filter."
)
RECOMMENDATION = (
    "Add allow directives for trusted CIDRs and a deny all fallback, or deny all "
    "for locations that should not be reachable."
)
SENSITIVE_LOCATION_PATHS = {"/admin", "/admin/", "/phpmyadmin", "/manage", "/internal"}
ACCESS_DIRECTIVES = frozenset({"allow", "deny"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    order=206,
)
def find_sensitive_location_missing_ip_filter(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    def visit(nodes: list[DirectiveNode | BlockNode], ancestors: tuple[BlockNode, ...]) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue

            block_chain = (*ancestors, node)
            if (
                node.name == "location"
                and _is_sensitive_location(node)
                and _has_basic_access_restriction(block_chain)
                and not _has_restrictive_ip_filter(block_chain)
            ):
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

            visit(node.children, block_chain)

    visit(config_ast.nodes, ())
    return findings


def _is_sensitive_location(location_block: BlockNode) -> bool:
    return any(arg.lower() in SENSITIVE_LOCATION_PATHS for arg in location_block.args)


def _has_basic_access_restriction(block_chain: tuple[BlockNode, ...]) -> bool:
    access_directives = _effective_access_directives(block_chain)
    if any(_is_restrictive_deny(directive) for directive in access_directives):
        return True

    has_restrictive_allow = any(
        _is_restrictive_allow(directive) for directive in access_directives
    )
    has_deny = any(directive.name == "deny" for directive in access_directives)
    if has_restrictive_allow and has_deny:
        return True

    auth_basic = _effective_auth_basic(block_chain)
    return auth_basic is not None and _is_auth_basic_enabled(auth_basic)


def _has_restrictive_ip_filter(block_chain: tuple[BlockNode, ...]) -> bool:
    has_deny_all = False
    for directive in _effective_access_directives(block_chain):
        if directive.name == "allow" and _directive_value(directive) == "all":
            return False
        if directive.name == "deny" and _directive_value(directive) == "all":
            has_deny_all = True
            break

    if not has_deny_all:
        return False
    return not _satisfy_any_allows_auth_bypass(block_chain)


def _effective_access_directives(block_chain: tuple[BlockNode, ...]) -> list[DirectiveNode]:
    for block in reversed(block_chain):
        directives = [
            child
            for child in block.children
            if isinstance(child, DirectiveNode) and child.name in ACCESS_DIRECTIVES
        ]
        if directives:
            return directives
    return []


def _effective_auth_basic(block_chain: tuple[BlockNode, ...]) -> DirectiveNode | None:
    for block in reversed(block_chain):
        directives = [
            child
            for child in block.children
            if isinstance(child, DirectiveNode) and child.name == "auth_basic"
        ]
        if directives:
            return directives[-1]
    return None


def _effective_satisfy(block_chain: tuple[BlockNode, ...]) -> DirectiveNode | None:
    for block in reversed(block_chain):
        directives = [
            child
            for child in block.children
            if isinstance(child, DirectiveNode) and child.name == "satisfy"
        ]
        if directives:
            return directives[-1]
    return None


def _satisfy_any_allows_auth_bypass(block_chain: tuple[BlockNode, ...]) -> bool:
    satisfy = _effective_satisfy(block_chain)
    auth_basic = _effective_auth_basic(block_chain)
    return (
        satisfy is not None
        and _directive_value(satisfy) == "any"
        and auth_basic is not None
        and _is_auth_basic_enabled(auth_basic)
    )


def _is_restrictive_deny(directive: DirectiveNode) -> bool:
    return bool(directive.args)


def _is_restrictive_allow(directive: DirectiveNode) -> bool:
    return _directive_value(directive) not in {"", "all"}


def _is_auth_basic_enabled(directive: DirectiveNode) -> bool:
    return _directive_value(directive) not in {"", "off"}


def _directive_value(directive: DirectiveNode) -> str:
    if not directive.args:
        return ""
    value = directive.args[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value.lower()


__all__ = ["find_sensitive_location_missing_ip_filter"]
