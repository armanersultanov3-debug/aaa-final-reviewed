from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
)
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021
from webconf_audit.tls_cipher_policy import (
    analyze_cipher_policy,
    describe_cipher_policy_issues,
)

RULE_ID = "nginx.ssl_ciphers_weak"
TITLE = "Nginx TLS cipher policy is weak"


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=(
        "Nginx ssl_ciphers allows weak components or lacks explicit modern "
        "cipher posture."
    ),
    recommendation=(
        "Configure ssl_ciphers with forward-secret AEAD cipher suites and "
        "remove weak components such as RC4, DES, 3DES, NULL, EXPORT, and MD5."
    ),
    category="local",
    server_type="nginx",
    tags=("tls",),
    standards=(
        cwe(327),
        owasp_top10_2021("A02:2021"),
        asvs_5(
            "12.1.2",
            coverage="partial",
            note="Conservative local cipher-string posture checks.",
        ),
    ),
    order=263,
)
def find_ssl_ciphers_weak(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    seen_inherited_directives: set[int] = set()

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"ssl_ciphers"},
    ):
        finding = _find_ssl_ciphers_weak_in_server(server_block, inherited_directives)
        if finding is None:
            continue
        inherited_directive_id = _inherited_ssl_ciphers_directive_id(
            server_block,
            inherited_directives,
        )
        if inherited_directive_id is not None:
            if inherited_directive_id in seen_inherited_directives:
                continue
            seen_inherited_directives.add(inherited_directive_id)
        findings.append(finding)

    return findings


def _inherited_ssl_ciphers_directive_id(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> int | None:
    server_directives = effective_child_directives(server_block, "ssl_ciphers", {})
    if server_directives:
        return None

    inherited_ssl_ciphers = inherited_directives.get("ssl_ciphers", [])
    if not inherited_ssl_ciphers:
        return None
    return id(inherited_ssl_ciphers[-1])


def _find_ssl_ciphers_weak_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> Finding | None:
    if not server_uses_tls(server_block):
        return None

    ssl_ciphers_directives = effective_child_directives(
        server_block,
        "ssl_ciphers",
        inherited_directives,
    )
    if not ssl_ciphers_directives:
        return None

    directive = ssl_ciphers_directives[-1]
    cipher_string = " ".join(directive.args)
    assessment = analyze_cipher_policy(cipher_string)
    if not assessment.has_issue:
        return None

    issues = "; ".join(describe_cipher_policy_issues(assessment))
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="medium",
        description=f"Nginx ssl_ciphers policy has weak posture: {issues}.",
        recommendation=(
            "Use explicit forward-secret AEAD suites, such as ECDHE AES-GCM "
            "or ECDHE CHACHA20-POLY1305 suites, and disable legacy algorithms."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.source.file_path,
            line=directive.source.line,
        ),
    )


__all__ = ["find_ssl_ciphers_weak"]
