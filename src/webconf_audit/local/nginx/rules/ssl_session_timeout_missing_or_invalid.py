"""Implements rule ``nginx.ssl_session_timeout_missing_or_invalid``.

Location: ``src/webconf_audit/local/nginx/rules/ssl_session_timeout_missing_or_invalid.py``.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
    parse_duration_seconds,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.ssl_session_timeout_missing_or_invalid"
TITLE = "Nginx TLS session timeout is missing or invalid"
MAX_TIMEOUT_SECONDS = 600.0


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=(
        "TLS server block does not define an explicit 'ssl_session_timeout' "
        "of 10 minutes or less."
    ),
    recommendation="Set 'ssl_session_timeout 10m;' or a lower non-zero value.",
    category="local",
    server_type="nginx",
    order=262,
    tags=("tls",),
)
def find_ssl_session_timeout_missing_or_invalid(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"ssl_session_timeout"},
    ):
        finding = _find_ssl_session_timeout_missing_or_invalid_in_server(
            server_block,
            inherited_directives,
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _find_ssl_session_timeout_missing_or_invalid_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> Finding | None:
    if not server_uses_tls(server_block):
        return None

    directives = effective_child_directives(
        server_block,
        "ssl_session_timeout",
        inherited_directives,
    )
    if not directives:
        return _finding(server_block, directive=None)

    directive = directives[-1]
    if not directive.args:
        return _finding(server_block, directive=directive)

    duration = parse_duration_seconds(directive.args[0])
    if duration is None or duration <= 0 or duration > MAX_TIMEOUT_SECONDS:
        return _finding(server_block, directive=directive)

    return None


def _finding(server_block: BlockNode, *, directive: DirectiveNode | None) -> Finding:
    source = directive.source if directive is not None else server_block.source
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="low",
        description=(
            "TLS server block does not define an explicit 'ssl_session_timeout' "
            "of 10 minutes or less."
        ),
        recommendation="Set 'ssl_session_timeout 10m;' or a lower non-zero value.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        ),
    )


__all__ = ["find_ssl_session_timeout_missing_or_invalid"]
