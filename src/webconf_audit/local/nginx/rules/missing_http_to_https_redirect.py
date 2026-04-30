from __future__ import annotations

from urllib.parse import urlparse

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import listen_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_http_to_https_redirect"

_REDIRECT_STATUS_CODES = {"301", "302", "307", "308"}
_LISTEN_OPTION_TOKENS = {
    "accept_filter",
    "backlog",
    "bind",
    "default_server",
    "deferred",
    "fastopen",
    "http2",
    "ipv6only",
    "proxy_protocol",
    "quic",
    "rcvbuf",
    "reuseaddr",
    "reuseport",
    "sndbuf",
    "so_keepalive",
    "ssl",
}


@rule(
    rule_id=RULE_ID,
    title="HTTP server block does not redirect to HTTPS",
    severity="low",
    description="A named HTTP server block does not return an HTTPS redirect.",
    recommendation="Redirect HTTP requests with 'return 301 https://$host$request_uri;'.",
    category="local",
    server_type="nginx",
    tags=("tls",),
    order=258,
)
def find_missing_http_to_https_redirect(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "server":
            continue
        if not _is_named_http_server(node) or _has_https_redirect(node):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="HTTP server block does not redirect to HTTPS",
                severity="low",
                description="Named HTTP server block listens without redirecting clients to HTTPS.",
                recommendation="Add 'return 301 https://$host$request_uri;' to the HTTP server block.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
            )
        )

    return findings


def _is_named_http_server(server_block: BlockNode) -> bool:
    if not find_child_directives(server_block, "server_name"):
        return False
    listen_directives = find_child_directives(server_block, "listen")
    if not listen_directives:
        return True
    return any(_listen_targets_http(directive) for directive in listen_directives)


def _listen_targets_http(directive: DirectiveNode) -> bool:
    lowered_args = {arg.lower() for arg in directive.args}
    if listen_uses_tls(directive) or "default_server" in lowered_args:
        return False
    return any(
        arg == "80" or arg.endswith(":80") or _is_implicit_http_listen_arg(arg)
        for arg in directive.args
    )


def _is_implicit_http_listen_arg(arg: str) -> bool:
    lowered = arg.lower()
    if lowered in _LISTEN_OPTION_TOKENS:
        return False
    if "/" in arg or "=" in arg or arg.isdigit():
        return False
    if arg.startswith("[") and arg.endswith("]"):
        return True
    return ":" not in arg


def _has_https_redirect(server_block: BlockNode) -> bool:
    for directive in find_child_directives(server_block, "return"):
        if not directive.args:
            continue
        if len(directive.args) == 1 and _is_https_redirect_target(directive.args[0]):
            return True
        if directive.args[0] not in _REDIRECT_STATUS_CODES:
            continue
        if len(directive.args) > 1 and _is_https_redirect_target(directive.args[1]):
            return True
    return False


def _is_https_redirect_target(target: str) -> bool:
    return urlparse(target.strip()).scheme.lower() == "https"


__all__ = ["find_missing_http_to_https_redirect"]
