from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._tls_policy_utils import (
    directive_args,
    iter_tls_scopes,
    make_tls_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule
from webconf_audit.tls_cipher_policy import (
    analyze_cipher_policy,
    describe_cipher_policy_issues,
)

RULE_ID = "apache.ssl_cipher_suite_weak"
TITLE = "Apache TLS cipher suite policy allows weak ciphers"


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description="Apache SSLCipherSuite allows weak or outdated cipher posture.",
    recommendation=(
        "Remove weak cipher components and use explicit forward-secret AEAD "
        "cipher suites in SSLCipherSuite."
    ),
    category="local",
    server_type="apache",
    order=357,
    tags=("tls",),
)
def find_ssl_cipher_suite_weak(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        directive = scope.directives.get("sslciphersuite")
        args = directive_args(directive)
        if directive is None or not args:
            continue

        assessment = analyze_cipher_policy(_cipher_policy(args))
        if not assessment.has_issue:
            continue

        issues = describe_cipher_policy_issues(assessment)
        findings.append(
            make_tls_finding(
                scope,
                rule_id=RULE_ID,
                title=TITLE,
                severity="medium",
                description=(
                    f"TLS scope '{scope.label}' has weak cipher posture: "
                    f"{'; '.join(issues)}."
                ),
                recommendation=(
                    "Remove weak cipher components and keep only explicit "
                    "forward-secret AEAD suites."
                ),
                directive=directive,
            )
        )
    return findings


def _cipher_policy(args: list[str]) -> str:
    if len(args) >= 2 and _looks_like_protocol_selector(args[0]):
        return " ".join(args[1:])
    return " ".join(args)


def _looks_like_protocol_selector(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("sslv", "tlsv"))


__all__ = ["find_ssl_cipher_suite_weak"]
