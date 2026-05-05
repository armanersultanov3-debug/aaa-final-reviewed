"""Small Content-Security-Policy parsing helpers."""

from __future__ import annotations


def content_security_policy_directives(header_value: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for part in header_value.replace(",", ";").split(";"):
        stripped = part.strip()
        if not stripped:
            continue
        directive_parts = stripped.split(None, 1)
        directive_name = directive_parts[0].lower()
        directive_value = directive_parts[1].strip() if len(directive_parts) > 1 else ""
        directives.setdefault(directive_name, directive_value)
    return directives


def content_security_policy_has_reporting_endpoint(header_value: str | None) -> bool:
    if header_value is None:
        return False
    directives = content_security_policy_directives(header_value)
    return any(
        bool(directives.get(directive_name, "").strip())
        for directive_name in ("report-uri", "report-to")
    )


__all__ = [
    "content_security_policy_directives",
    "content_security_policy_has_reporting_endpoint",
]
