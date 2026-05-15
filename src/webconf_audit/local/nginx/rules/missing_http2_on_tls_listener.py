"""nginx.missing_http2_on_tls_listener -- TLS listener missing http2 parameter."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import listen_uses_tls_on_port_443
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
    last_directive_is_on,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_http2_on_tls_listener"


@rule(
    rule_id=RULE_ID,
    title="TLS listener missing http2 parameter",
    severity="low",
    description=(
        "TLS listen directive exposes port 443 with 'ssl' but does not enable "
        "HTTP/2."
    ),
    recommendation="Add 'http2' to this TLS listen directive when HTTP/2 is intended.",
    category="local",
    server_type="nginx",
    order=218,
)
def find_missing_http2_on_tls_listener(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"http2"},
    ):
        findings.extend(
            _find_missing_http2_on_tls_listener_in_server(
                server_block,
                inherited_directives,
            )
        )

    return findings


def _find_missing_http2_on_tls_listener_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> list[Finding]:
    findings: list[Finding] = []

    if _server_has_http2_enabled(server_block, inherited_directives):
        return []

    for directive in find_child_directives(server_block, "listen"):
        if not listen_uses_tls_on_port_443(directive) or "http2" in directive.args:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="TLS listener missing http2 parameter",
                severity="low",
                description=(
                    "TLS listen directive exposes port 443 with 'ssl' but does not enable "
                    f"'http2': {' '.join(directive.args)!r}."
                ),
                recommendation="Add 'http2' to this TLS listen directive when HTTP/2 is intended.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


def _server_has_http2_enabled(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> bool:
    return last_directive_is_on(
        effective_child_directives(server_block, "http2", inherited_directives)
    )


__all__ = ["find_missing_http2_on_tls_listener"]
