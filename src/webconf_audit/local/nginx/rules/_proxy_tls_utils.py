from __future__ import annotations

from dataclasses import dataclass

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_blocks_with_inherited_directives,
    last_directive_is_on,
)

_PROXY_TLS_SCOPE_NAMES = {"http", "server", "location"}
_PROXY_TLS_DIRECTIVE_NAMES = {
    "proxy_ssl_trusted_certificate",
    "proxy_ssl_verify",
}


@dataclass(frozen=True)
class ProxyTlsScope:
    block: BlockNode
    proxy_ssl_verify_directives: list[DirectiveNode]
    trusted_certificate_directives: list[DirectiveNode]


def iter_https_proxy_scopes(config_ast: ConfigAst) -> list[ProxyTlsScope]:
    scopes: list[ProxyTlsScope] = []

    for block, inherited_directives in iter_blocks_with_inherited_directives(
        config_ast,
        _PROXY_TLS_DIRECTIVE_NAMES,
        block_names=_PROXY_TLS_SCOPE_NAMES,
    ):
        if not _has_https_proxy_pass(block):
            continue

        scopes.append(
            ProxyTlsScope(
                block=block,
                proxy_ssl_verify_directives=effective_child_directives(
                    block,
                    "proxy_ssl_verify",
                    inherited_directives,
                ),
                trusted_certificate_directives=effective_child_directives(
                    block,
                    "proxy_ssl_trusted_certificate",
                    inherited_directives,
                ),
            )
        )

    return scopes


def proxy_ssl_verify_is_on(directives: list[DirectiveNode]) -> bool:
    return last_directive_is_on(directives)


def trusted_certificate_is_configured(directives: list[DirectiveNode]) -> bool:
    if not directives:
        return False
    last = directives[-1]
    return bool(last.args and last.args[0].strip())


def _has_https_proxy_pass(block: BlockNode) -> bool:
    for child in block.children:
        if not isinstance(child, DirectiveNode):
            continue
        if child.name != "proxy_pass" or not child.args:
            continue
        if child.args[0].lower().startswith("https://"):
            return True
    return False


__all__ = [
    "ProxyTlsScope",
    "iter_https_proxy_scopes",
    "proxy_ssl_verify_is_on",
    "trusted_certificate_is_configured",
]
