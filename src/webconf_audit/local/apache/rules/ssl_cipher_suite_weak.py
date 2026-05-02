from __future__ import annotations

import re

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._tls_policy_utils import (
    directive_args,
    iter_tls_scopes,
    make_tls_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ssl_cipher_suite_weak"
TITLE = "Apache TLS cipher suite policy allows weak ciphers"
_WEAK_MARKERS = (
    "des-cbc3",
    "3des",
    "export",
    "anull",
    "enull",
    "null",
    "rc4",
    "md5",
    "des",
    "adh",
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description="Apache SSLCipherSuite allows known weak cipher components.",
    recommendation=(
        "Remove weak cipher components such as RC4, DES, 3DES, NULL, EXPORT, "
        "aNULL, eNULL, ADH, and MD5 from SSLCipherSuite."
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

        weak_markers = _weak_cipher_markers(_cipher_policy(args))
        if not weak_markers:
            continue

        findings.append(
            make_tls_finding(
                scope,
                rule_id=RULE_ID,
                title=TITLE,
                severity="medium",
                description=(
                    f"TLS scope '{scope.label}' allows weak cipher "
                    f"component(s): {', '.join(weak_markers)}."
                ),
                recommendation=(
                    "Remove weak cipher components and keep only modern "
                    "authenticated encryption suites."
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


def _weak_cipher_markers(cipher_policy: str) -> list[str]:
    found: set[str] = set()
    for token in _cipher_tokens(cipher_policy):
        if token.startswith(("!", "-", "+!")):
            continue
        if token.upper() == "ALL":
            found.add("ALL")
            continue
        normalized = token.lower()
        for marker in _WEAK_MARKERS:
            if marker in normalized:
                found.add(marker.upper())
                break
    return sorted(found)


def _cipher_tokens(cipher_policy: str) -> list[str]:
    return [
        token.strip()
        for token in re.split(r"[:\s,]+", cipher_policy)
        if token.strip()
    ]


__all__ = ["find_ssl_cipher_suite_weak"]
