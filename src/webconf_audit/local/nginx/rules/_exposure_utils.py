from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    DirectiveNode,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    last_directive_is_on,
)


def server_has_public_autoindex(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> bool:
    if last_directive_is_on(
        effective_child_directives(server_block, "autoindex", inherited_directives)
    ):
        return True

    return any(
        isinstance(node, BlockNode)
        and node.name == "location"
        and last_directive_is_on(find_child_directives(node, "autoindex"))
        for node in iter_nodes(server_block.children)
    )


def public_autoindex_missing_limit_metadata(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> dict[str, str]:
    if not server_has_public_autoindex(server_block, inherited_directives):
        return {}

    return {"severity_reason": "public_autoindex_without_request_limits"}


__all__ = [
    "public_autoindex_missing_limit_metadata",
    "server_has_public_autoindex",
]
