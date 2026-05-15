"""Shared TLS cipher-string parser and weakness classifier.

Backs the ``weak_tls_ciphers`` family of rules across Nginx, Apache,
Lighttpd, and IIS. Parses OpenSSL-style cipher lists, recognises
disabled tokens (``!``/``-``), and classifies tokens by the weakness
they introduce (no forward secrecy, no AEAD, known-broken primitives).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_TOKEN_SPLIT_RE = re.compile(r"[:\s,]+")
_TOKEN_PART_SPLIT_RE = re.compile(r"[-_+]")
_DISABLED_PREFIXES = ("!", "-")
_BROAD_SELECTOR_TOKENS = frozenset(
    {
        "DEFAULT",
        "HIGH",
        "FIPS",
        "SUITEB128",
        "SUITEB128ONLY",
        "SUITEB192",
        "TLSV1",
        "TLSV1.2",
        "TLSV1.3",
    }
)
_WEAK_EXACT_TOKENS = {
    "ALL": "ALL",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "COMPLEMENTOFALL": "COMPLEMENTOFALL",
}
_WEAK_SUBSTRINGS = (
    ("DES-CBC3", "3DES"),
    ("3DES", "3DES"),
    ("EXPORT", "EXPORT"),
    ("EXP", "EXPORT"),
    ("ANULL", "ANULL"),
    ("ENULL", "ENULL"),
    ("AECDH", "AECDH"),
    ("ADH", "ADH"),
    ("NULL", "NULL"),
    ("RC4", "RC4"),
    ("MD5", "MD5"),
)


@dataclass(frozen=True, slots=True)
class CipherPolicyAssessment:
    weak_markers: tuple[str, ...] = ()
    missing_forward_secrecy: bool = False
    missing_aead: bool = False

    @property
    def has_issue(self) -> bool:
        return bool(
            self.weak_markers
            or self.missing_forward_secrecy
            or self.missing_aead
        )


def analyze_cipher_policy(cipher_string: str) -> CipherPolicyAssessment:
    tokens = _enabled_cipher_tokens(cipher_string)
    concrete_tokens = [token for token in tokens if _is_concrete_cipher_token(token)]
    weak_markers = _weak_markers(tokens)

    return CipherPolicyAssessment(
        weak_markers=tuple(sorted(weak_markers)),
        missing_forward_secrecy=bool(concrete_tokens)
        and any(not _has_forward_secrecy(token) for token in concrete_tokens),
        missing_aead=bool(concrete_tokens)
        and any(not _has_aead(token) for token in concrete_tokens),
    )


def describe_cipher_policy_issues(assessment: CipherPolicyAssessment) -> list[str]:
    issues: list[str] = []
    if assessment.weak_markers:
        issues.append(f"weak components: {', '.join(assessment.weak_markers)}")
    if assessment.missing_forward_secrecy:
        issues.append("cipher suites without forward secrecy")
    if assessment.missing_aead:
        issues.append("cipher suites without AEAD")
    return issues


def _enabled_cipher_tokens(cipher_string: str) -> list[str]:
    tokens: list[str] = []
    for raw_token in _TOKEN_SPLIT_RE.split(cipher_string):
        token = raw_token.strip().strip('"').strip("'")
        if not token or token.startswith("@"):
            continue
        if token.startswith(_DISABLED_PREFIXES):
            continue
        tokens.append(token.lstrip("+").upper())
    return tokens


def _weak_markers(tokens: list[str]) -> set[str]:
    markers: set[str] = set()
    for token in tokens:
        if token in _WEAK_EXACT_TOKENS:
            markers.add(_WEAK_EXACT_TOKENS[token])
        if _contains_standalone_des(token):
            markers.add("DES")
        for needle, marker in _WEAK_SUBSTRINGS:
            if needle in token:
                markers.add(marker)
    if "3DES" in markers:
        markers.discard("DES")
    return markers


def _contains_standalone_des(token: str) -> bool:
    parts = _TOKEN_PART_SPLIT_RE.split(token)
    return "DES" in parts


def _is_concrete_cipher_token(token: str) -> bool:
    if token in _BROAD_SELECTOR_TOKENS or token in _WEAK_EXACT_TOKENS:
        return False
    return any(separator in token for separator in ("-", "_", "+"))


def _is_tls13_cipher(token: str) -> bool:
    return token.startswith(("TLS_AES_", "TLS_CHACHA20_"))


def _has_forward_secrecy(token: str) -> bool:
    if _is_tls13_cipher(token):
        return True
    if any(marker in token for marker in ("ANULL", "AECDH", "ADH")):
        return False
    parts = _TOKEN_PART_SPLIT_RE.split(token)
    return any(part in parts for part in ("ECDHE", "EECDH", "DHE", "EDH"))


def _has_aead(token: str) -> bool:
    if _is_tls13_cipher(token):
        return True
    return any(marker in token for marker in ("GCM", "CHACHA20", "POLY1305", "CCM"))


__all__ = [
    "CipherPolicyAssessment",
    "analyze_cipher_policy",
    "describe_cipher_policy_issues",
]
