from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_ssl_protocols"


@rule(
    rule_id=RULE_ID,
    title="Missing ssl_protocols directive",
    severity="medium",
    description="TLS server block does not define an effective 'ssl_protocols' policy.",
    recommendation="Set 'ssl_protocols TLSv1.2 TLSv1.3;' in http or server scope.",
    category="local",
    server_type="nginx",
    tags=("tls",),
    order=231,
)
def find_missing_ssl_protocols(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"ssl_protocols"},
    ):
        finding = _find_missing_ssl_protocols_in_server(server_block, inherited_directives)
        if finding is not None:
            findings.append(finding)

    return findings


def _find_missing_ssl_protocols_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> Finding | None:
    if not server_uses_tls(server_block):
        return None

    ssl_protocols_directives = effective_child_directives(
        server_block,
        "ssl_protocols",
        inherited_directives,
    )
    if ssl_protocols_directives:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing ssl_protocols directive",
        severity="medium",
        description="TLS server block does not define an effective 'ssl_protocols' policy.",
        recommendation="Set 'ssl_protocols TLSv1.2 TLSv1.3;' in http or server scope.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


__all__ = ["find_missing_ssl_protocols"]
