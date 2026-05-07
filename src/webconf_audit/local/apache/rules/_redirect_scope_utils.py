from __future__ import annotations

from urllib.parse import urlparse

from webconf_audit.local.apache.effective import ApacheVirtualHostContext
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheDirectiveNode
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    iter_enabled_nodes,
)

_REDIRECT_STATUSES = frozenset(
    {"301", "302", "303", "307", "308", "permanent", "temp", "temporary", "seeother"}
)
_TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)
_REDIRECT_METADATA_DIRECTIVES = frozenset(
    {
        "customlog",
        "errorlog",
        "loglevel",
        "rewriteengine",
        "serveradmin",
        "serveralias",
        "servername",
        "usecanonicalname",
    }
)
_WHOLE_PATHS = frozenset({"", "/"})
_WHOLE_PATTERNS = frozenset(
    {
        "^",
        "^/",
        "^/(.*)$",
        "^/(.*)",
        "^.*$",
        "^(.*)$",
        "^(.*)",
        ".*",
    }
)


def is_redirect_only_virtualhost(
    context: ApacheVirtualHostContext,
    modules: frozenset[str] = frozenset(),
) -> bool:
    if not _virtualhost_listens_on_http(context):
        return False
    return _block_scope_state(context.node, modules) is True


def has_whole_https_redirect(
    block: ApacheBlockNode,
    modules: frozenset[str] = frozenset(),
) -> bool:
    for node in iter_enabled_nodes(block.children, modules):
        if isinstance(node, ApacheBlockNode):
            continue

        if _directive_redirects_all_to_https(node) is True:
            return True
    return False


def _block_scope_state(
    block: ApacheBlockNode,
    modules: frozenset[str],
) -> bool | None:
    has_whole_https_redirect = False
    for node in iter_enabled_nodes(block.children, modules):
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() not in _TRANSPARENT_WRAPPER_BLOCKS:
                return False
            child_state = _block_scope_state(node, modules)
            if child_state is False:
                return False
            if child_state is None:
                continue
            has_whole_https_redirect = True
            continue

        directive_result = _directive_redirects_all_to_https(node)
        if directive_result is True:
            has_whole_https_redirect = True
            continue
        if directive_result is False:
            return False
        if node.name.lower() not in _REDIRECT_METADATA_DIRECTIVES:
            return False

    return True if has_whole_https_redirect else None


def _directive_redirects_all_to_https(
    directive: ApacheDirectiveNode,
) -> bool | None:
    name = directive.name.lower()
    if name == "redirect":
        return _redirect_directive_targets_whole_https(directive)
    if name == "redirectmatch":
        return _redirect_match_targets_whole_https(directive)
    if name == "rewriterule":
        return _rewrite_rule_targets_whole_https(directive)
    if name == "rewritecond":
        return False
    return None


def _redirect_directive_targets_whole_https(
    directive: ApacheDirectiveNode,
) -> bool:
    args = _drop_redirect_status(directive.args)
    return (
        len(args) >= 2
        and args[0].strip().strip('"').strip("'") in _WHOLE_PATHS
        and _is_https_target(args[1])
    )


def _redirect_match_targets_whole_https(
    directive: ApacheDirectiveNode,
) -> bool:
    args = _drop_redirect_status(directive.args)
    return (
        len(args) >= 2
        and _is_whole_pattern(args[0])
        and _is_https_target(args[1])
    )


def _rewrite_rule_targets_whole_https(
    directive: ApacheDirectiveNode,
) -> bool:
    if len(directive.args) < 2:
        return False
    return (
        _is_whole_pattern(directive.args[0])
        and _is_https_target(directive.args[1])
        and any(_rewrite_flags_redirect(arg) for arg in directive.args[2:])
    )


def _drop_redirect_status(args: list[str]) -> list[str]:
    if args and args[0].lower() in _REDIRECT_STATUSES:
        return args[1:]
    return args


def _rewrite_flags_redirect(value: str) -> bool:
    normalized = value.strip().strip("[]").lower()
    return any(
        flag in {"r", "redirect"} or flag.startswith(("r=", "redirect="))
        for flag in normalized.split(",")
    )


def _is_whole_pattern(value: str) -> bool:
    return value.strip().strip('"').strip("'") in _WHOLE_PATTERNS


def _is_https_target(value: str) -> bool:
    return urlparse(value.strip().strip('"').strip("'")).scheme.lower() == "https"


def _virtualhost_listens_on_http(context: ApacheVirtualHostContext) -> bool:
    addresses = context.listen_addresses
    if not addresses and context.listen_address is not None:
        addresses = (context.listen_address,)
    return any(_address_port(address) == 80 for address in addresses)


def _address_port(value: str) -> int | None:
    if value.isdigit():
        return int(value)
    if ":" not in value:
        return None
    _, _, port = value.rpartition(":")
    if not port.isdigit():
        return None
    return int(port)


__all__ = ["has_whole_https_redirect", "is_redirect_only_virtualhost"]
