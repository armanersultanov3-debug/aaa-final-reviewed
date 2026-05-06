from __future__ import annotations

from webconf_audit.local.apache.effective import ApacheVirtualHostContext
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheDirectiveNode

TRANSPARENT_WRAPPER_BLOCKS = frozenset({"ifdefine", "ifmodule", "ifversion"})
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


def rejects_unknown_hosts(block: ApacheBlockNode) -> bool:
    return _has_whole_scope_require_all_denied(block) or _has_forbidden_rewrite(block)


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


def _has_whole_scope_require_all_denied(block: ApacheBlockNode) -> bool:
    for node in block.children:
        if isinstance(node, ApacheDirectiveNode):
            continue
        name = node.name.lower()
        if name in TRANSPARENT_WRAPPER_BLOCKS:
            if _has_whole_scope_require_all_denied(node):
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
    block: ApacheBlockNode, *, rewrite_engine_enabled: bool = False
) -> bool:
    found, _ = _scan_forbidden_rewrite(
        block,
        rewrite_engine_enabled=rewrite_engine_enabled,
    )
    return found


def _scan_forbidden_rewrite(
    block: ApacheBlockNode, *, rewrite_engine_enabled: bool
) -> tuple[bool, bool]:
    for node in block.children:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
                found, rewrite_engine_enabled = _scan_forbidden_rewrite(
                    node,
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
