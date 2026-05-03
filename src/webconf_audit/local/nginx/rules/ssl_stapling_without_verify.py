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

RULE_ID = "nginx.ssl_stapling_without_verify"


@rule(
    rule_id=RULE_ID,
    title="SSL stapling enabled without verification",
    severity="low",
    description="Server block enables 'ssl_stapling' without 'ssl_stapling_verify on'.",
    recommendation="Set 'ssl_stapling_verify on;' in this server block.",
    category="local",
    server_type="nginx",
    order=239,
)
def find_ssl_stapling_without_verify(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"ssl_stapling", "ssl_stapling_verify"},
    ):
        finding = _find_ssl_stapling_without_verify_in_server(
            server_block,
            inherited_directives,
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _find_ssl_stapling_without_verify_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> Finding | None:
    ssl_stapling_directives = effective_child_directives(
        server_block,
        "ssl_stapling",
        inherited_directives,
    )
    ssl_stapling_verify_directives = effective_child_directives(
        server_block,
        "ssl_stapling_verify",
        inherited_directives,
    )

    uses_tls = server_uses_tls(server_block)
    stapling_on = last_directive_is_on(ssl_stapling_directives)
    stapling_verify_on = last_directive_is_on(ssl_stapling_verify_directives)

    if not uses_tls or not stapling_on or stapling_verify_on:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="SSL stapling enabled without verification",
        severity="low",
        description="Server block enables 'ssl_stapling' without 'ssl_stapling_verify on'.",
        recommendation="Set 'ssl_stapling_verify on;' in this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


__all__ = ["find_ssl_stapling_without_verify"]
