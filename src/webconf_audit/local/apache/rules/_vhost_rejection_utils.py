from __future__ import annotations

from webconf_audit.local.apache.effective import ApacheVirtualHostContext
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheDirectiveNode
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    ifmodule_matches,
)

TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"ifdefine", "ifmodule", "ifversion", "requireall"}
)
WHOLE_PATHS = frozenset({"", "/"})
WHOLE_PATTERNS = frozenset(
    {
        "^",
        "^/",
        "^/.*$",
        "^/.*",
        "^/(.*)$",
        "^/(.*)",
        "^.*$",
        "^(.*)$",
        "^(.*)",
        ".*",
    }
)


def listen_keys(context: ApacheVirtualHostContext) -> list[str]:
    addresses = context.listen_addresses
    if not addresses and context.listen_address is not None:
        addresses = (context.listen_address,)
    return list(dict.fromkeys(_normalize_listen_key(address) for address in addresses))


def rejects_unknown_hosts(
    block: ApacheBlockNode,
    modules: frozenset[str] = frozenset(),
) -> bool:
    return _has_whole_scope_require_all_denied(block, modules) or _has_forbidden_rewrite(
        block,
        modules=modules,
    )


def _normalize_listen_key(value: str) -> str:
    value = value.strip()
    if value.isdigit():
        return f"*:{value}"
    if value.startswith("[") and "]" in value:
        host, _, remainder = value[1:].partition("]")
        port = remainder[1:] if remainder.startswith(":") else ""
        return f"{_normalize_host(host)}:{port}" if port else _normalize_host(host)
    if ":" not in value:
        return value.lower()
    host, _, port = value.rpartition(":")
    if not port.isdigit():
        return value.lower()
    return f"{_normalize_host(host)}:{port}"


def _normalize_host(value: str) -> str:
    normalized = value.strip().strip("[]").lower()
    if normalized in {"", "*", "_default_"}:
        return "*"
    return normalized


def _has_whole_scope_require_all_denied(
    block: ApacheBlockNode,
    modules: frozenset[str],
) -> bool:
    for node in _iter_guarded_nodes(block.children, modules):
        if isinstance(node, ApacheDirectiveNode):
            continue
        name = node.name.lower()
        if name in TRANSPARENT_WRAPPER_BLOCKS:
            if _has_whole_scope_require_all_denied(node, modules):
                return True
        elif _is_whole_request_scope(node) and _has_require_all_denied(node):
            return True
    return False


def _has_require_all_denied(block: ApacheBlockNode) -> bool:
    for node in block.children:
        if isinstance(node, ApacheDirectiveNode):
            if _is_require_all_denied(node):
                return True
            continue
        if node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
            if _has_require_all_denied(node):
                return True
    return False


def _is_require_all_denied(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "require"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "all"
        and directive.args[1].lower() == "denied"
    )


def _is_whole_request_scope(block: ApacheBlockNode) -> bool:
    if not block.args:
        return False
    name = block.name.lower()
    value = block.args[0].strip().strip('"').strip("'")
    if name == "location":
        return value in WHOLE_PATHS
    if name == "locationmatch":
        return value in WHOLE_PATTERNS
    return False


def _has_forbidden_rewrite(
    block: ApacheBlockNode,
    modules: frozenset[str],
    *,
    rewrite_engine_enabled: bool = False,
) -> bool:
    found, _ = _scan_forbidden_rewrite(
        block,
        modules=modules,
        rewrite_engine_enabled=rewrite_engine_enabled,
    )
    return found


def _scan_forbidden_rewrite(
    block: ApacheBlockNode,
    modules: frozenset[str],
    *,
    rewrite_engine_enabled: bool,
) -> tuple[bool, bool]:
    for node in _iter_guarded_nodes(block.children, modules):
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
                found, rewrite_engine_enabled = _scan_forbidden_rewrite(
                    node,
                    modules=modules,
                    rewrite_engine_enabled=rewrite_engine_enabled,
                )
                if found:
                    return True, rewrite_engine_enabled
            continue

        if node.name.lower() == "rewriteengine" and node.args:
            rewrite_engine_enabled = (
                node.args[0].strip().strip('"').strip("'").lower() == "on"
            )
            continue
        if rewrite_engine_enabled and _is_forbidden_rewrite_rule(node):
            return True, rewrite_engine_enabled
    return False, rewrite_engine_enabled


def _iter_guarded_nodes(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> list[ApacheDirectiveNode | ApacheBlockNode]:
    guarded: list[ApacheDirectiveNode | ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            guarded.append(node)
            continue

        name = node.name.lower()
        if name == "ifmodule":
            if ifmodule_matches(node.args, modules):
                guarded.extend(_iter_guarded_nodes(node.children, modules))
            continue
        if name in {"ifdefine", "ifversion"}:
            guarded.extend(_iter_guarded_nodes(node.children, modules))
            continue

        guarded.append(node)
    return guarded


def _is_forbidden_rewrite_rule(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "rewriterule"
        and len(directive.args) >= 3
        and _is_whole_pattern(directive.args[0])
        and directive.args[1] == "-"
        and _rewrite_rule_rejects(directive.args[2:])
    )


def _is_whole_pattern(value: str) -> bool:
    return value.strip().strip('"').strip("'") in WHOLE_PATTERNS


def _rewrite_rule_rejects(args: list[str]) -> bool:
    for arg in args:
        normalized = arg.strip().strip("[]").lower()
        flags = [part.strip() for part in normalized.split(",")]
        if any(
            flag in {"f", "forbidden", "g", "gone"}
            or flag in {"r=400", "redirect=400", "r=403", "redirect=403"}
            or flag in {"r=404", "redirect=404"}
            for flag in flags
        ):
            return True
    return False


__all__ = ["listen_keys", "rejects_unknown_hosts"]
