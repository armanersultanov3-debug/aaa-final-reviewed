"""nginx.ssl_session_tickets_disabled -- TLS session tickets are disabled."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import iter_direct_child_directives
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.ssl_session_tickets_disabled"


@rule(
    rule_id=RULE_ID,
    title="TLS session tickets are disabled",
    severity="low",
    description="Nginx explicitly disables TLS session tickets with 'ssl_session_tickets off'.",
    recommendation="Remove 'ssl_session_tickets off' or set 'ssl_session_tickets on'.",
    category="local",
    server_type="nginx",
    order=246,
)
def find_ssl_session_tickets_disabled(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive, _parent in iter_direct_child_directives(
        config_ast,
        "ssl_session_tickets",
        block_names={"http", "server"},
    ):
        if not directive.args or directive.args[0].lower() != "off":
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="TLS session tickets are disabled",
                severity="low",
                description="Nginx explicitly disables TLS session tickets with 'ssl_session_tickets off'.",
                recommendation="Remove 'ssl_session_tickets off' or set 'ssl_session_tickets on'.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


__all__ = ["find_ssl_session_tickets_disabled"]
