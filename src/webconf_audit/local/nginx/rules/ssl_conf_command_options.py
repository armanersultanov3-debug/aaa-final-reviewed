from __future__ import annotations

from collections.abc import Callable

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, Severity, SourceLocation
from webconf_audit.openssl_conf_policy import ssl_conf_option_state
from webconf_audit.rule_registry import rule

COMPRESSION_RULE_ID = "nginx.ssl_conf_command_tls_compression_enabled"
COMPRESSION_TITLE = "Nginx OpenSSL TLS compression is enabled"

RENEGOTIATION_RULE_ID = "nginx.ssl_conf_command_unsafe_renegotiation_enabled"
RENEGOTIATION_TITLE = "Nginx unsafe TLS renegotiation is enabled"


@rule(
    rule_id=COMPRESSION_RULE_ID,
    title=COMPRESSION_TITLE,
    severity="medium",
    description=(
        "Nginx ssl_conf_command explicitly enables OpenSSL TLS compression."
    ),
    recommendation=(
        "Remove the Compression option or set ssl_conf_command Options "
        "-Compression."
    ),
    category="local",
    server_type="nginx",
    tags=("tls",),
    order=266,
)
def find_ssl_conf_command_tls_compression_enabled(
    config_ast: ConfigAst,
) -> list[Finding]:
    return _find_option_enabled(
        config_ast,
        option_name="Compression",
        rule_id=COMPRESSION_RULE_ID,
        title=COMPRESSION_TITLE,
        severity="medium",
        description=lambda _scope: (
            "Nginx TLS scope explicitly enables OpenSSL TLS compression via "
            "ssl_conf_command Options Compression."
        ),
        recommendation=(
            "Disable TLS compression by removing the Compression option or "
            "setting ssl_conf_command Options -Compression."
        ),
    )


@rule(
    rule_id=RENEGOTIATION_RULE_ID,
    title=RENEGOTIATION_TITLE,
    severity="high",
    description=(
        "Nginx ssl_conf_command explicitly enables unsafe legacy TLS "
        "renegotiation."
    ),
    recommendation=(
        "Remove UnsafeLegacyRenegotiation from ssl_conf_command Options."
    ),
    category="local",
    server_type="nginx",
    tags=("tls",),
    order=267,
)
def find_ssl_conf_command_unsafe_renegotiation_enabled(
    config_ast: ConfigAst,
) -> list[Finding]:
    return _find_option_enabled(
        config_ast,
        option_name="UnsafeLegacyRenegotiation",
        rule_id=RENEGOTIATION_RULE_ID,
        title=RENEGOTIATION_TITLE,
        severity="high",
        description=lambda _scope: (
            "Nginx TLS scope explicitly enables unsafe legacy TLS "
            "renegotiation via ssl_conf_command Options "
            "UnsafeLegacyRenegotiation."
        ),
        recommendation=(
            "Remove UnsafeLegacyRenegotiation from ssl_conf_command Options."
        ),
    )


def _find_option_enabled(
    config_ast: ConfigAst,
    *,
    option_name: str,
    rule_id: str,
    title: str,
    severity: Severity,
    description: Callable[[BlockNode], str],
    recommendation: str,
) -> list[Finding]:
    findings: list[Finding] = []
    seen_inherited_directives: set[int] = set()

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"ssl_conf_command"},
    ):
        directive = _effective_enabled_ssl_conf_command(
            server_block,
            inherited_directives,
            option_name=option_name,
        )
        if directive is None:
            continue

        inherited_directive_id = _inherited_directive_id(
            server_block,
            inherited_directives,
            directive,
        )
        if inherited_directive_id is not None:
            if inherited_directive_id in seen_inherited_directives:
                continue
            seen_inherited_directives.add(inherited_directive_id)

        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                description=description(server_block),
                recommendation=recommendation,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


def _effective_enabled_ssl_conf_command(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
    *,
    option_name: str,
) -> DirectiveNode | None:
    if not server_uses_tls(server_block):
        return None

    enabled_directive: DirectiveNode | None = None
    for directive in effective_child_directives(
        server_block,
        "ssl_conf_command",
        inherited_directives,
    ):
        option_state = _ssl_conf_command_option_state(directive, option_name)
        if option_state is None:
            continue
        enabled_directive = directive if option_state else None
    return enabled_directive


def _ssl_conf_command_option_state(
    directive: DirectiveNode,
    option_name: str,
) -> bool | None:
    if len(directive.args) < 2 or directive.args[0].lower() != "options":
        return None
    return ssl_conf_option_state(" ".join(directive.args[1:]), option_name)


def _inherited_directive_id(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
    directive: DirectiveNode,
) -> int | None:
    server_directives = effective_child_directives(server_block, "ssl_conf_command", {})
    if server_directives:
        return None
    if not any(
        candidate is directive
        for candidate in inherited_directives.get("ssl_conf_command", [])
    ):
        return None
    return id(directive)


__all__ = [
    "find_ssl_conf_command_tls_compression_enabled",
    "find_ssl_conf_command_unsafe_renegotiation_enabled",
]
