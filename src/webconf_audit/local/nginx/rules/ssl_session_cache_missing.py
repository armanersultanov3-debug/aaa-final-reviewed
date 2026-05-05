from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.ssl_session_cache_missing"
TITLE = "Nginx TLS session cache is missing or disabled"
DISABLED_VALUES = frozenset({"off", "none"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description="TLS server block does not define a usable 'ssl_session_cache'.",
    recommendation="Set 'ssl_session_cache shared:SSL:10m;' in http or server scope.",
    category="local",
    server_type="nginx",
    order=261,
    tags=("tls",),
)
def find_ssl_session_cache_missing(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"ssl_session_cache"},
    ):
        finding = _find_ssl_session_cache_missing_in_server(
            server_block,
            inherited_directives,
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _find_ssl_session_cache_missing_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> Finding | None:
    if not server_uses_tls(server_block):
        return None

    directives = effective_child_directives(
        server_block,
        "ssl_session_cache",
        inherited_directives,
    )
    if directives:
        directive = directives[-1]
        first_value = directive.args[0].lower() if directive.args else ""
        if first_value not in DISABLED_VALUES:
            return None
        return _finding(server_block, directive=directive)

    return _finding(server_block, directive=None)


def _finding(server_block: BlockNode, *, directive: DirectiveNode | None) -> Finding:
    source = directive.source if directive is not None else server_block.source
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="low",
        description="TLS server block does not define a usable 'ssl_session_cache'.",
        recommendation="Set 'ssl_session_cache shared:SSL:10m;' in http or server scope.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        ),
    )


__all__ = ["find_ssl_session_cache_missing"]
