"""lighttpd.weak_ssl_cipher_list -- Weak SSL ciphers configured."""

from __future__ import annotations

from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import iter_all_nodes, unquote
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.tls_cipher_policy import (
    analyze_cipher_policy,
    describe_cipher_policy_issues,
)

RULE_ID = "lighttpd.weak_ssl_cipher_list"


@rule(
    rule_id=RULE_ID,
    title="Weak SSL ciphers configured",
    severity="high",
    description="Weak SSL ciphers configured",
    recommendation="Remove weak ciphers and use only strong cipher suites.",
    category="local",
    server_type="lighttpd",
    tags=("tls",),
    order=414,
)
def find_weak_ssl_cipher_list(config_ast: LighttpdConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != "ssl.cipher-list":
            continue

        assessment = analyze_cipher_policy(unquote(node.value))
        if not assessment.has_issue:
            continue

        issues = describe_cipher_policy_issues(assessment)
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Weak SSL ciphers configured",
                severity="high",
                description=(
                    "ssl.cipher-list has weak cipher posture: "
                    f"{'; '.join(issues)}."
                ),
                recommendation=(
                    "Remove weak ciphers and use explicit forward-secret AEAD "
                    "cipher suites."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
            )
        )

    return findings


__all__ = ["find_weak_ssl_cipher_list"]
