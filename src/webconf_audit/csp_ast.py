"""Structured Content-Security-Policy parsing helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re


class CspDisposition(str, Enum):
    ENFORCE = "enforce"
    REPORT = "report"


class CspTokenKind(str, Enum):
    KEYWORD = "keyword"
    NONCE = "nonce"
    HASH = "hash"
    SCHEME = "scheme"
    HOST = "host"
    WILDCARD = "wildcard"
    DYNAMIC_TEMPLATE = "dynamic_template"
    TOKEN = "token"
    UNKNOWN = "unknown"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class CspToken:
    kind: CspTokenKind
    raw: str
    normalized: str
    valid: bool
    details: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CspParseIssue:
    code: str
    message: str
    policy_index: int | None
    directive_index: int | None
    token_index: int | None
    fatal_for_structure: bool


@dataclass(frozen=True, slots=True)
class CspDirective:
    name: str
    raw_name: str
    raw_value: str
    tokens: tuple[CspToken, ...]
    directive_index: int
    effective: bool
    duplicate_of: int | None


@dataclass(frozen=True, slots=True)
class CspPolicy:
    disposition: CspDisposition
    raw_text: str
    policy_index: int
    directives: tuple[CspDirective, ...]
    issues: tuple[CspParseIssue, ...]

    def first_directive(self, name: str) -> CspDirective | None:
        wanted = name.lower()
        for directive in self.directives:
            if directive.name == wanted and directive.effective:
                return directive
        return None


@dataclass(frozen=True, slots=True)
class CspParsedHeaderValue:
    disposition: CspDisposition
    raw_value: str
    policies: tuple[CspPolicy, ...]
    issues: tuple[CspParseIssue, ...]


_DYNAMIC_VARIABLE_RE = re.compile(r"\$(?:\{(?P<braced>[A-Za-z0-9_]+)\}|(?P<plain>[A-Za-z0-9_]+))")
_DIRECTIVE_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:$")
_HOST_SOURCE_RE = re.compile(
    r"^(?:(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://)?(?P<host>\*|\*\.[^/:]+|[^/:]+)(?::(?P<port>\*|[0-9]+))?(?P<path>/.*)?$"
)
_HASH_RE = re.compile(r"^(sha256|sha384|sha512)-([A-Za-z0-9+/=]+)$", re.IGNORECASE)

_KNOWN_KEYWORDS = frozenset(
    {
        "'none'",
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'strict-dynamic'",
        "'unsafe-hashes'",
        "'report-sample'",
        "'wasm-unsafe-eval'",
    }
)
_KNOWN_SOURCE_LIST_DIRECTIVES = frozenset(
    {
        "default-src",
        "script-src",
        "script-src-elem",
        "script-src-attr",
        "style-src",
        "style-src-elem",
        "style-src-attr",
        "img-src",
        "font-src",
        "connect-src",
        "media-src",
        "object-src",
        "manifest-src",
        "worker-src",
        "child-src",
        "frame-src",
        "frame-ancestors",
        "base-uri",
        "form-action",
    }
)
_KNOWN_DIRECTIVES = _KNOWN_SOURCE_LIST_DIRECTIVES | frozenset(
    {
        "report-uri",
        "report-to",
        "sandbox",
        "upgrade-insecure-requests",
        "block-all-mixed-content",
        "require-trusted-types-for",
        "trusted-types",
    }
)


def parse_csp_header_value(
    header_value: str,
    *,
    disposition: CspDisposition,
) -> CspParsedHeaderValue:
    issues: list[CspParseIssue] = []
    if _contains_dynamic_structure(header_value):
        issues.append(
            CspParseIssue(
                code="dynamic-structure",
                message="Header value contains variables and may expand to additional policies or directives at runtime.",
                policy_index=None,
                directive_index=None,
                token_index=None,
                fatal_for_structure=False,
            )
        )

    policies: list[CspPolicy] = []
    for policy_index, raw_policy in enumerate(_split_top_level(header_value, ",")):
        policy_text = raw_policy.strip()
        policy_issues: list[CspParseIssue] = []
        if not policy_text:
            issue = CspParseIssue(
                code="empty-policy-member",
                message="Serialized CSP policy list contains an empty member.",
                policy_index=policy_index,
                directive_index=None,
                token_index=None,
                fatal_for_structure=False,
            )
            policy_issues.append(issue)
            issues.append(issue)
            continue

        directives: list[CspDirective] = []
        seen_directive_names: dict[str, int] = {}
        for directive_index, raw_directive in enumerate(_split_top_level(policy_text, ";")):
            directive_text = raw_directive.strip()
            if not directive_text:
                issue = CspParseIssue(
                    code="empty-directive-member",
                    message="Serialized CSP policy contains an empty directive member.",
                    policy_index=policy_index,
                    directive_index=directive_index,
                    token_index=None,
                    fatal_for_structure=False,
                )
                policy_issues.append(issue)
                issues.append(issue)
                continue

            parts = directive_text.split(None, 1)
            raw_name = parts[0]
            name = raw_name.lower()
            raw_value = parts[1].strip() if len(parts) == 2 else ""

            if not _DIRECTIVE_NAME_RE.match(raw_name):
                issue = CspParseIssue(
                    code="invalid-directive-name",
                    message=f"Directive name {raw_name!r} is not a valid CSP token.",
                    policy_index=policy_index,
                    directive_index=directive_index,
                    token_index=None,
                    fatal_for_structure=False,
                )
                policy_issues.append(issue)
                issues.append(issue)

            if name not in _KNOWN_DIRECTIVES:
                issue = CspParseIssue(
                    code="unknown-directive",
                    message=f"Directive {raw_name!r} is not a recognized CSP directive.",
                    policy_index=policy_index,
                    directive_index=directive_index,
                    token_index=None,
                    fatal_for_structure=False,
                )
                policy_issues.append(issue)
                issues.append(issue)

            duplicate_of = seen_directive_names.get(name)
            effective = duplicate_of is None
            if duplicate_of is None:
                seen_directive_names[name] = directive_index
            else:
                issue = CspParseIssue(
                    code="duplicate-directive",
                    message=f"Directive {name!r} is duplicated; later copies are ignored by CSP parsing.",
                    policy_index=policy_index,
                    directive_index=directive_index,
                    token_index=None,
                    fatal_for_structure=False,
                )
                policy_issues.append(issue)
                issues.append(issue)

            tokens = tuple(
                _parse_csp_token(
                    name,
                    token,
                    policy_index=policy_index,
                    directive_index=directive_index,
                    token_index=token_index,
                    issues=issues,
                    policy_issues=policy_issues,
                )
                for token_index, token in enumerate(_split_directive_value(raw_value))
            )
            directives.append(
                CspDirective(
                    name=name,
                    raw_name=raw_name,
                    raw_value=raw_value,
                    tokens=tokens,
                    directive_index=directive_index,
                    effective=effective,
                    duplicate_of=duplicate_of,
                )
            )

        policies.append(
            CspPolicy(
                disposition=disposition,
                raw_text=policy_text,
                policy_index=policy_index,
                directives=tuple(directives),
                issues=tuple(policy_issues),
            )
        )

    return CspParsedHeaderValue(
        disposition=disposition,
        raw_value=header_value,
        policies=tuple(policies),
        issues=tuple(issues),
    )


def _contains_dynamic_structure(value: str) -> bool:
    return "$" in value


def _split_top_level(value: str, separator: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for char in value:
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char == separator:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _split_directive_value(value: str) -> list[str]:
    if not value:
        return []
    return [token for token in value.split() if token]


def _parse_csp_token(
    directive_name: str,
    token: str,
    *,
    policy_index: int,
    directive_index: int,
    token_index: int,
    issues: list[CspParseIssue],
    policy_issues: list[CspParseIssue],
) -> CspToken:
    normalized = token.lower()
    if _DYNAMIC_VARIABLE_RE.search(token):
        kind = CspTokenKind.DYNAMIC_TEMPLATE
        if normalized.startswith("'nonce-") and normalized.endswith("'"):
            kind = CspTokenKind.NONCE
            return CspToken(
                kind=kind,
                raw=token,
                normalized=normalized,
                valid=True,
                details={
                    "nonce_kind": "dynamic_template",
                    "variables": _extract_variables(token),
                },
            )
        return CspToken(
            kind=kind,
            raw=token,
            normalized=token,
            valid=True,
            details={"variables": _extract_variables(token)},
        )

    if normalized in _KNOWN_KEYWORDS:
        return CspToken(
            kind=CspTokenKind.KEYWORD,
            raw=token,
            normalized=normalized,
            valid=True,
        )

    if normalized.startswith("'nonce-") and normalized.endswith("'"):
        nonce_value = token[7:-1]
        valid = bool(nonce_value)
        details = {
            "nonce_kind": "static_literal",
            "fingerprint": _fingerprint(token),
        }
        if not valid:
            issue = CspParseIssue(
                code="invalid-nonce",
                message=f"Nonce source {token!r} is invalid.",
                policy_index=policy_index,
                directive_index=directive_index,
                token_index=token_index,
                fatal_for_structure=False,
            )
            policy_issues.append(issue)
            issues.append(issue)
        return CspToken(
            kind=CspTokenKind.NONCE,
            raw=token,
            normalized=normalized,
            valid=valid,
            details=details,
        )

    hash_match = _HASH_RE.match(token)
    if hash_match is not None:
        return CspToken(
            kind=CspTokenKind.HASH,
            raw=token,
            normalized=f"{hash_match.group(1).lower()}-{hash_match.group(2)}",
            valid=True,
            details={
                "algorithm": hash_match.group(1).lower(),
                "fingerprint": _fingerprint(hash_match.group(2)),
            },
        )

    if token == "*":
        return CspToken(
            kind=CspTokenKind.WILDCARD,
            raw=token,
            normalized=token,
            valid=True,
        )

    if _SCHEME_RE.match(token):
        return CspToken(
            kind=CspTokenKind.SCHEME,
            raw=token,
            normalized=normalized,
            valid=True,
        )

    host_match = _HOST_SOURCE_RE.match(token)
    if directive_name in _KNOWN_SOURCE_LIST_DIRECTIVES and host_match is not None:
        return CspToken(
            kind=CspTokenKind.HOST,
            raw=token,
            normalized=normalized,
            valid=True,
            details={
                "scheme": host_match.group("scheme"),
                "host": host_match.group("host"),
                "port": host_match.group("port"),
                "path": host_match.group("path"),
            },
        )

    if directive_name in _KNOWN_SOURCE_LIST_DIRECTIVES:
        issue = CspParseIssue(
            code="unknown-source-expression",
            message=f"Token {token!r} is not a recognized CSP source expression.",
            policy_index=policy_index,
            directive_index=directive_index,
            token_index=token_index,
            fatal_for_structure=False,
        )
        policy_issues.append(issue)
        issues.append(issue)
        return CspToken(
            kind=CspTokenKind.UNKNOWN,
            raw=token,
            normalized=token,
            valid=False,
        )

    return CspToken(
        kind=CspTokenKind.TOKEN,
        raw=token,
        normalized=token,
        valid=True,
    )


def _extract_variables(value: str) -> tuple[str, ...]:
    return tuple(
        f"${match.group('braced') or match.group('plain')}"
        for match in _DYNAMIC_VARIABLE_RE.finditer(value)
    )


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "CspDirective",
    "CspDisposition",
    "CspParsedHeaderValue",
    "CspParseIssue",
    "CspPolicy",
    "CspToken",
    "CspTokenKind",
    "parse_csp_header_value",
]
