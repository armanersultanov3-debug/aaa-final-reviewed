from __future__ import annotations

from collections import defaultdict

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules._default_server_rejection_utils import (
    rejects_unknown_hosts,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import (
    listen_is_default_server,
    listen_key,
    listen_uses_tls,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule
from webconf_audit.standards import owasp_top10_2021

RULE_ID = "nginx.default_tls_server_not_rejecting_unknown_hosts"
TITLE = "Default TLS server does not reject unknown hosts"
DESCRIPTION = (
    "Multiple TLS servers share a listen address, but the implicit first/default "
    "TLS server does not reject unexpected host names."
)
RECOMMENDATION = (
    "Add a dedicated TLS catch-all server (or an explicit 'default_server') for "
    "the shared listen key and reject unknown hosts with 'ssl_reject_handshake on;' "
    "or a 4xx/444 return."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    standards=(
        owasp_top10_2021("A05:2021"),
        StandardReference(
            standard="CIS",
            reference="NGINX v3.0.0 §2.4.2",
            url="https://www.cisecurity.org/benchmark/nginx",
            coverage="partial",
            note="Implicit first/default TLS server catch-all rejection only.",
        ),
    ),
    order=255,
    tags=("tls",),
)
def find_default_tls_server_not_rejecting_unknown_hosts(
    config_ast: ConfigAst,
) -> list[Finding]:
    findings_by_server: dict[int, tuple[BlockNode, list[str]]] = defaultdict(
        lambda: (None, [])  # type: ignore[return-value]
    )

    for key, server_block in _default_tls_servers_by_listen_key(config_ast).items():
        if rejects_unknown_hosts(server_block):
            continue
        entry = findings_by_server.get(id(server_block))
        if entry is None:
            findings_by_server[id(server_block)] = (server_block, [key])
            continue
        entry[1].append(key)

    return [
        _finding(server_block, listen_keys)
        for server_block, listen_keys in findings_by_server.values()
    ]


def _default_tls_servers_by_listen_key(config_ast: ConfigAst) -> dict[str, BlockNode]:
    servers_by_key: dict[str, list[BlockNode]] = defaultdict(list)
    explicit_defaults: dict[str, BlockNode] = {}

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "server":
            continue
        for directive in find_child_directives(node, "listen"):
            if not listen_uses_tls(directive):
                continue
            key = listen_key(directive)
            if key is None:
                continue
            servers_by_key[key].append(node)
            if listen_is_default_server(directive):
                explicit_defaults.setdefault(key, node)

    return {
        key: server_blocks[0]
        for key, server_blocks in servers_by_key.items()
        if len(server_blocks) > 1 and key not in explicit_defaults
    }


def _finding(server_block: BlockNode, listen_keys: list[str]) -> Finding:
    server_name = _server_label(server_block)
    formatted_keys = ", ".join(sorted(set(listen_keys)))
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="low",
        description=(
            f"Nginx TLS server '{server_name}' is the implicit default for {formatted_keys} "
            "and can serve requests for unknown host names."
        ),
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


def _server_label(server_block: BlockNode) -> str:
    server_names = find_child_directives(server_block, "server_name")
    if not server_names or not server_names[-1].args:
        return "<unnamed>"
    return " ".join(server_names[-1].args)


__all__ = ["find_default_tls_server_not_rejecting_unknown_hosts"]
