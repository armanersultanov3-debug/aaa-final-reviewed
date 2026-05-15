"""Implements rule ``nginx.server_block_accepts_unknown_host``.

Location: ``src/webconf_audit/local/nginx/rules/server_block_accepts_unknown_host.py``.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode, find_child_directives
from webconf_audit.local.nginx.rules._default_server_rejection_utils import rejects_unknown_hosts
from webconf_audit.local.nginx.rules.tls_listener_utils import listen_is_default_server
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cwe, owasp_top10_2021

RULE_ID = "nginx.server_block_accepts_unknown_host"
TITLE = "Non-default server accepts unexpected Host values"
DESCRIPTION = (
    "A non-default Nginx server block has no strict host match and still serves "
    "content or proxies traffic without explicitly rejecting unknown Host values."
)
RECOMMENDATION = (
    "Define explicit server_name values for content-serving servers and add a "
    "catch-all rejection path for unexpected Host values."
)
_CONTENT_HANDLER_DIRECTIVES = frozenset(
    {
        "alias",
        "fastcgi_pass",
        "grpc_pass",
        "proxy_pass",
        "root",
        "scgi_pass",
        "try_files",
        "uwsgi_pass",
    }
)
_NEGATIVE_HOST_TOKENS = frozenset({"!=", "!~", "!~*"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("host", "routing"),
    standards=(
        cwe(346),
        owasp_top10_2021("A05:2021"),
    ),
    order=275,
)
def find_server_block_accepts_unknown_host(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in _iter_http_server_blocks(config_ast):
        if _is_default_server(node):
            continue
        if not _has_loose_server_name(node):
            continue
        if rejects_unknown_hosts(node) or _has_host_guard_reject(node):
            continue
        if not _has_content_handler(node):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="medium",
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


def _iter_http_server_blocks(config_ast: ConfigAst) -> list[BlockNode]:
    servers: list[BlockNode] = []

    def walk(nodes: list[BlockNode | DirectiveNode], *, in_http: bool = False) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue
            child_in_http = in_http or node.name == "http"
            if node.name == "server" and in_http:
                servers.append(node)
                continue
            walk(node.children, in_http=child_in_http)

    walk(config_ast.nodes)
    return servers


def _is_default_server(server_block: BlockNode) -> bool:
    return any(
        listen_is_default_server(directive)
        for directive in find_child_directives(server_block, "listen")
    )


def _has_loose_server_name(server_block: BlockNode) -> bool:
    server_names = find_child_directives(server_block, "server_name")
    if not server_names:
        return True
    args = server_names[-1].args
    if not args:
        return True
    return any(argument == "_" or "*" in argument for argument in args)


def _has_host_guard_reject(server_block: BlockNode) -> bool:
    for child in server_block.children:
        if not isinstance(child, BlockNode) or child.name != "if":
            continue
        if not child.args or "$host" not in child.args[0].lower():
            continue
        if not any(token.lower() in _NEGATIVE_HOST_TOKENS for token in child.args[1:]):
            continue
        if any(
            isinstance(grandchild, DirectiveNode)
            and grandchild.name == "return"
            and grandchild.args
            and grandchild.args[0] in {"400", "403", "404", "421", "444"}
            for grandchild in child.children
        ):
            return True
    return False


def _has_content_handler(block: BlockNode) -> bool:
    for child in block.children:
        if isinstance(child, DirectiveNode) and child.name in _CONTENT_HANDLER_DIRECTIVES:
            return True
        if isinstance(child, BlockNode) and _has_content_handler(child):
            return True
    return False


__all__ = ["find_server_block_accepts_unknown_host"]
