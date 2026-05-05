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
    if "*" in cleaned:
        return False
    return any("=" in directive for directive in _split_permissions_directives(cleaned))


def x_frame_options_is_safe(value: str | None) -> bool:
    if value is None:
        return False
    return _clean_header_value(value).upper() in {"DENY", "SAMEORIGIN"}


def content_security_policy_has_frame_ancestors(value: str | None) -> bool:
    if value is None:
        return False
    directives = content_security_policy_directives(_clean_header_value(value))
    return bool(directives.get("frame-ancestors", "").strip())


def _clean_header_value(value: str) -> str:
    return value.strip().strip('"').strip("'")


def _split_permissions_directives(value: str) -> list[str]:
    return [
        directive.strip()
        for directive in value.replace(";", ",").split(",")
        if directive.strip()
    ]


__all__ = [
    "content_security_policy_has_frame_ancestors",
    "permissions_policy_is_safe",
    "referrer_policy_is_safe",
    "x_frame_options_is_safe",
]
