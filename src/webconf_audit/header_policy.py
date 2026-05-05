"""Shared helpers for conservative security header quality checks."""

from __future__ import annotations

from webconf_audit.csp import content_security_policy_directives

_SAFE_REFERRER_POLICIES = frozenset({"no-referrer", "strict-origin-when-cross-origin"})
_KNOWN_REFERRER_POLICIES = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
)


def referrer_policy_is_safe(value: str | None) -> bool:
    if value is None:
        return False
    cleaned = _clean_header_value(value).lower()
    if not cleaned:
        return False
    tokens = [token.strip() for token in cleaned.split(",") if token.strip()]
    for token in reversed(tokens):
        if token in _KNOWN_REFERRER_POLICIES:
            return token in _SAFE_REFERRER_POLICIES
    return False


def permissions_policy_is_safe(value: str | None) -> bool:
    if value is None:
        return False
    cleaned = _clean_header_value(value)
    if not cleaned:
        return False
    directives = _split_permissions_directives(cleaned)
    if any(_permissions_directive_has_bare_wildcard(directive) for directive in directives):
        return False
    return any("=" in directive for directive in directives)


def x_frame_options_is_safe(value: str | None) -> bool:
    if value is None:
        return False
    return _clean_header_value(value).upper() in {"DENY", "SAMEORIGIN"}


def content_security_policy_has_frame_ancestors(value: str | None) -> bool:
    if value is None:
        return False
    directives = content_security_policy_directives(_clean_header_value(value))
    frame_ancestors = directives.get("frame-ancestors", "")
    tokens = [token.strip() for token in frame_ancestors.split() if token.strip()]
    if not tokens:
        return False
    if any(_is_bare_wildcard_frame_ancestor_token(token) for token in tokens):
        return False
    return any(_is_restrictive_frame_ancestor_token(token) for token in tokens)


def _clean_header_value(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {"'", '"'}:
        return cleaned[1:-1].strip()
    return cleaned


def _split_permissions_directives(value: str) -> list[str]:
    return [
        directive.strip()
        for directive in value.replace(";", ",").split(",")
        if directive.strip()
    ]


def _permissions_directive_has_bare_wildcard(directive: str) -> bool:
    if "=" not in directive:
        return False
    _, _, allowlist = directive.partition("=")
    normalized = "".join(allowlist.strip().lower().split())
    return normalized in {"*", "'*'", '"*"', "(*)", "('*')", '("*")'}


def _is_restrictive_frame_ancestor_token(token: str) -> bool:
    normalized = token.lower()
    return normalized in {"'none'", "'self'"} or _is_explicit_origin(normalized)


def _is_bare_wildcard_frame_ancestor_token(token: str) -> bool:
    return token.lower() in {"*", "'*'", '"*"'}


def _is_explicit_origin(token: str) -> bool:
    for scheme in ("https://", "http://"):
        if token.startswith(scheme) and len(token) > len(scheme):
            origin_part = token[len(scheme):]
            host = origin_part.split("/", 1)[0].split(":", 1)[0]
            if not host or host == "*":
                return False
            return True
    return False


__all__ = [
    "content_security_policy_has_frame_ancestors",
    "permissions_policy_is_safe",
    "referrer_policy_is_safe",
    "x_frame_options_is_safe",
]
