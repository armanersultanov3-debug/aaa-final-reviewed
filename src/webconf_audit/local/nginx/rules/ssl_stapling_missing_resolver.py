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

RULE_ID = "nginx.ssl_stapling_missing_resolver"


@rule(
    rule_id=RULE_ID,
    title="SSL stapling enabled without resolver",
    severity="low",
    description="Server block enables 'ssl_stapling' but does not define 'resolver'.",
    recommendation="Add a 'resolver' directive to this server block.",
    category="local",
    server_type="nginx",
    order=238,
)
def find_ssl_stapling_missing_resolver(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"resolver", "ssl_stapling"},
    ):
        finding = _find_ssl_stapling_missing_resolver_in_server(
            server_block,
            inherited_directives,
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _find_ssl_stapling_missing_resolver_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> Finding | None:
    ssl_stapling_directives = effective_child_directives(
        server_block,
        "ssl_stapling",
        inherited_directives,
    )
    resolver_directives = effective_child_directives(
        server_block,
        "resolver",
        inherited_directives,
    )

    uses_tls = server_uses_tls(server_block)
    stapling_on = last_directive_is_on(ssl_stapling_directives)

    if not uses_tls or not stapling_on or _resolver_is_present(resolver_directives):
        return None

    return Finding(
        rule_id=RULE_ID,
        title="SSL stapling enabled without resolver",
        severity="low",
        description="Server block enables 'ssl_stapling' but does not define 'resolver'.",
        recommendation="Add a 'resolver' directive to this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


def _resolver_is_present(directives: list[DirectiveNode]) -> bool:
    if not directives:
        return False
    last = directives[-1]
    return bool(last.args) and last.args[0].lower() != "off"


__all__ = ["find_ssl_stapling_missing_resolver"]
