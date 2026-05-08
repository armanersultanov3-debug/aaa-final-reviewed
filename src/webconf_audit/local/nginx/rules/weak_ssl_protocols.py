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
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021, rfc

RULE_ID = "nginx.weak_ssl_protocols"
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@rule(
    rule_id=RULE_ID,
    title="Weak SSL/TLS protocols enabled",
    severity="medium",
    description="Nginx explicitly enables weak SSL/TLS protocols via ssl_protocols.",
    recommendation="Remove SSLv2, SSLv3, TLSv1, and TLSv1.1 from the ssl_protocols directive.",
    category="local",
    server_type="nginx",
    standards=(
        cwe(327),
        owasp_top10_2021("A02:2021"),
        asvs_5("12.1.1"),
        rfc(
            8996,
            coverage="partial",
            note="Flags RFC 8996-deprecated TLS 1.0 / 1.1 alongside adjacent legacy SSLv2/SSLv3 posture.",
        ),
    ),
    order=240,
)
def find_weak_ssl_protocols(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    seen_inherited_directives: set[int] = set()

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"ssl_protocols"},
    ):
        finding = _find_weak_ssl_protocols_in_server(server_block, inherited_directives)
        if finding is not None:
            inherited_directive_id = _inherited_ssl_protocols_directive_id(
                server_block,
                inherited_directives,
            )
            if inherited_directive_id is not None:
                if inherited_directive_id in seen_inherited_directives:
                    continue
                seen_inherited_directives.add(inherited_directive_id)
            findings.append(finding)

    return findings


def _inherited_ssl_protocols_directive_id(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> int | None:
    if find_child_directives(server_block, "ssl_protocols"):
        return None

    inherited_ssl_protocols = inherited_directives.get("ssl_protocols", [])
    if not inherited_ssl_protocols:
        return None

    return id(inherited_ssl_protocols[-1])


def _find_weak_ssl_protocols_in_server(
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
    if not ssl_protocols_directives:
        return None

    directive = ssl_protocols_directives[-1]
    weak_protocols = [protocol for protocol in directive.args if protocol in WEAK_PROTOCOLS]
    if not weak_protocols:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Weak SSL/TLS protocols enabled",
        severity="medium",
        description=(
            "Nginx explicitly enables weak SSL/TLS protocols via "
            f"'ssl_protocols {' '.join(directive.args)};'."
        ),
        recommendation="Remove SSLv2, SSLv3, TLSv1, and TLSv1.1 from the ssl_protocols directive.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.source.file_path,
            line=directive.source.line,
        ),
    )


__all__ = ["find_weak_ssl_protocols"]
