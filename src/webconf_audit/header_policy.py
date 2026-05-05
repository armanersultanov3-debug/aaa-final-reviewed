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
    return bool(directives) and all(
        _permissions_directive_has_valid_structure(directive)
        for directive in directives
    )


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
    lowered_tokens = {token.lower() for token in tokens}
    if lowered_tokens == {"'none'"}:
        return True
    if "'none'" in lowered_tokens:
        return False
    if any(_is_permissive_frame_ancestor_token(token) for token in tokens):
        return False
    return all(_is_restrictive_frame_ancestor_token(token) for token in tokens)


def _clean_header_value(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {"'", '"'}:
        return cleaned[1:-1].strip()
    return cleaned


def _split_permissions_directives(value: str) -> list[str]:
    directives: list[str] = []
    current: list[str] = []
    depth = 0
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
        if char == "(":
            depth += 1
            current.append(char)
            continue
        if char == ")":
            depth = max(depth - 1, 0)
            current.append(char)
            continue
        if char in {",", ";"} and depth == 0:
            directive = "".join(current).strip()
            if directive:
                directives.append(directive)
            current = []
            continue
        current.append(char)

    directive = "".join(current).strip()
    if directive:
        directives.append(directive)
    return directives


def _permissions_directive_has_bare_wildcard(directive: str) -> bool:
    if "=" not in directive:
        return False
    _, _, allowlist = directive.partition("=")
    normalized = "".join(allowlist.strip().lower().split())
    return normalized in {"*", "'*'", '"*"', "(*)", "('*')", '("*")'}


def _permissions_directive_has_valid_structure(directive: str) -> bool:
    if "=" not in directive:
        return False
    name, _, allowlist = directive.partition("=")
    name = name.strip()
    allowlist = allowlist.strip()
    if not name or not allowlist:
        return False
    if _permissions_directive_has_bare_wildcard(directive):
        return True
    return allowlist.startswith("(") and allowlist.endswith(")")


def _is_restrictive_frame_ancestor_token(token: str) -> bool:
    normalized = token.lower()
    return normalized in {"'none'", "'self'"} or _is_explicit_origin(normalized)


def _is_bare_wildcard_frame_ancestor_token(token: str) -> bool:
    return token.lower() in {"*", "'*'", '"*"'}


def _is_permissive_frame_ancestor_token(token: str) -> bool:
    normalized = token.lower()
    if _is_bare_wildcard_frame_ancestor_token(normalized):
        return True
    if normalized in {"http:", "https:"}:
        return True
    for scheme in ("https://", "http://"):
        if normalized.startswith(scheme):
            host = normalized[len(scheme):].split("/", 1)[0].split(":", 1)[0]
            return not host or host == "*"
    return False


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
