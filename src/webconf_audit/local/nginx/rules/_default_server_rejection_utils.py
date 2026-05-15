"""Internal helpers for the default server rejection utils rule family.

Location: ``src/webconf_audit/local/nginx/rules/_default_server_rejection_utils.py``.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, find_child_directives

_REJECT_STATUS_CODES = frozenset({"400", "403", "404", "444"})


def rejects_unknown_hosts(server_block: BlockNode) -> bool:
    for directive in find_child_directives(server_block, "ssl_reject_handshake"):
        if directive.args and directive.args[0].lower() == "on":
            return True

    for directive in find_child_directives(server_block, "return"):
        if directive.args and directive.args[0] in _REJECT_STATUS_CODES:
            return True

    return False


__all__ = ["rejects_unknown_hosts"]
