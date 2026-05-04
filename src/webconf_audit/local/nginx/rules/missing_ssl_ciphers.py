from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
)
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_ssl_ciphers"


@rule(
    rule_id=RULE_ID,
    title="Missing ssl_ciphers directive",
    severity="medium",
    description="Server block uses TLS but does not define 'ssl_ciphers'.",
    recommendation="Add an 'ssl_ciphers' directive to this server block.",
    category="local",
    server_type="nginx",
    order=232,
)
def find_missing_ssl_ciphers(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"ssl_ciphers"},
    ):
        finding = _find_missing_ssl_ciphers_in_server(server_block, inherited_directives)
        if finding is not None:
            findings.append(finding)

    return findings


def _find_missing_ssl_ciphers_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> Finding | None:
    server_ssl_protocols_directives = find_child_directives(
        server_block,
        "ssl_protocols",
    )
    ssl_ciphers_directives = effective_child_directives(
        server_block,
        "ssl_ciphers",
        inherited_directives,
    )

    uses_tls = server_uses_tls(server_block) or bool(server_ssl_protocols_directives)

    if not uses_tls or ssl_ciphers_directives:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing ssl_ciphers directive",
        severity="medium",
        description="Server block uses TLS but does not define 'ssl_ciphers'.",
        recommendation="Add an 'ssl_ciphers' directive to this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


__all__ = ["find_missing_ssl_ciphers"]
