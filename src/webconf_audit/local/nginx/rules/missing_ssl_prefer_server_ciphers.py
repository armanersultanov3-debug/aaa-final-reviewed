"""nginx.missing_ssl_prefer_server_ciphers -- Missing ssl_prefer_server_ciphers directive."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
    last_directive_is_on,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_ssl_prefer_server_ciphers"


@rule(
    rule_id=RULE_ID,
    title="Missing ssl_prefer_server_ciphers directive",
    severity="low",
    description=(
        "Server block uses TLS and defines 'ssl_ciphers' but does not set "
        "'ssl_prefer_server_ciphers on'."
    ),
    recommendation="Set 'ssl_prefer_server_ciphers on;' in this server block.",
    category="local",
    server_type="nginx",
    order=233,
)
def find_missing_ssl_prefer_server_ciphers(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"ssl_ciphers", "ssl_prefer_server_ciphers"},
    ):
        finding = _find_missing_ssl_prefer_server_ciphers_in_server(
            server_block,
            inherited_directives,
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _find_missing_ssl_prefer_server_ciphers_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> Finding | None:
    ssl_ciphers_directives = effective_child_directives(
        server_block,
        "ssl_ciphers",
        inherited_directives,
    )
    ssl_prefer_server_ciphers_directives = effective_child_directives(
        server_block,
        "ssl_prefer_server_ciphers",
        inherited_directives,
    )

    uses_tls = server_uses_tls(server_block)
    prefers_server_ciphers = last_directive_is_on(ssl_prefer_server_ciphers_directives)

    if not uses_tls or not ssl_ciphers_directives or prefers_server_ciphers:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing ssl_prefer_server_ciphers directive",
        severity="low",
        description=(
            "Server block uses TLS and defines 'ssl_ciphers' but does not set "
            "'ssl_prefer_server_ciphers on'."
        ),
        recommendation="Set 'ssl_prefer_server_ciphers on;' in this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


__all__ = ["find_missing_ssl_prefer_server_ciphers"]
