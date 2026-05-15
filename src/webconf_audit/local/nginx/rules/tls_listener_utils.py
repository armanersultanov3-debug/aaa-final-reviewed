"""Rule module: tls listener utils.

Location: ``src/webconf_audit/local/nginx/rules/tls_listener_utils.py``.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, DirectiveNode, find_child_directives

_LISTEN_OPTION_TOKENS = frozenset(
    {
        "bind",
        "default_server",
        "deferred",
        "http2",
        "proxy_protocol",
        "quic",
        "reuseport",
        "setfib",
        "so_keepalive",
        "ssl",
        "transparent",
    }
)
_LISTEN_OPTION_PREFIXES = (
    "accept_filter=",
    "backlog=",
    "fastopen=",
    "ipv6only=",
    "rcvbuf=",
    "sndbuf=",
    "so_keepalive=",
)


def listen_uses_tls(directive: DirectiveNode) -> bool:
    return "ssl" in directive.args


def listen_uses_tls_on_port_443(directive: DirectiveNode) -> bool:
    return listen_uses_tls(directive) and any(_listen_arg_targets_port_443(arg) for arg in directive.args)


def server_uses_tls(server_block: BlockNode) -> bool:
    return any(
        listen_uses_tls(directive)
        for directive in find_child_directives(server_block, "listen")
    )


def listen_key(directive: DirectiveNode) -> str | None:
    token = _listen_target_token(directive)
    if token is None:
        return None
    if token.isdigit():
        return f"*:{token}"
    return token.lower()


def listen_is_default_server(directive: DirectiveNode) -> bool:
    return any(arg.lower() == "default_server" for arg in directive.args)


def _listen_target_token(directive: DirectiveNode) -> str | None:
    for arg in directive.args:
        if _is_listen_option(arg):
            continue
        return arg
    return None


def _is_listen_option(arg: str) -> bool:
    normalized = arg.strip().lower()
    return normalized in _LISTEN_OPTION_TOKENS or any(
        normalized.startswith(prefix)
        for prefix in _LISTEN_OPTION_PREFIXES
    )


def _listen_arg_targets_port_443(arg: str) -> bool:
    return arg == "443" or arg.endswith(":443")


__all__ = [
    "listen_is_default_server",
    "listen_key",
    "listen_uses_tls",
    "listen_uses_tls_on_port_443",
    "server_uses_tls",
]
