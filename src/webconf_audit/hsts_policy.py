"""Shared HSTS (Strict-Transport-Security) policy helpers.

Centralises the minimum ``max-age`` value and the policy-strength
evaluation used by both local and external HSTS rules so the wording
of "weak HSTS" stays consistent across server families.
"""

from __future__ import annotations

import re

MIN_HSTS_MAX_AGE = 31_536_000


def hsts_policy_reason(
    value: str,
    *,
    require_include_subdomains: bool = True,
) -> str | None:
    if "$" in value:
        return None

    directives = _hsts_directives(value)
    max_age = directives.get("max-age")
    if max_age is None:
        return "missing max-age directive"
    if not re.fullmatch(r"\d+", max_age):
        return "max-age is not a positive integer"
    if int(max_age) < MIN_HSTS_MAX_AGE:
        return f"max-age is below {MIN_HSTS_MAX_AGE} seconds"
    if require_include_subdomains and "includesubdomains" not in directives:
        return "missing includeSubDomains directive"
    return None


def _hsts_directives(value: str) -> dict[str, str | None]:
    directives: dict[str, str | None] = {}
    for part in _strip_quotes(value).split(";"):
        item = part.strip()
        if not item:
            continue
        name, separator, raw_value = item.partition("=")
        directives[name.strip().lower()] = raw_value.strip() if separator else None
    return directives


def _strip_quotes(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        return stripped[1:-1]
    return stripped


__all__ = ["MIN_HSTS_MAX_AGE", "hsts_policy_reason"]
