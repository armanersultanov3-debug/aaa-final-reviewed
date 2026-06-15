"""Content-Security-Policy helpers and compatibility adapters."""

from __future__ import annotations

from webconf_audit.csp_ast import (
    CspDirective,
    CspDisposition,
    CspParsedHeaderValue,
    CspParseIssue,
    CspPolicy,
    CspToken,
    CspTokenKind,
    parse_csp_header_value,
)


def content_security_policy_directives(header_value: str) -> dict[str, str]:
    """Return the first-policy compatibility view for legacy callers."""
    parsed = parse_csp_header_value(
        header_value,
        disposition=CspDisposition.ENFORCE,
    )
    first_policy = parsed.policies[0] if parsed.policies else None
    if first_policy is None:
        return {}
    directives: dict[str, str] = {}
    for directive in first_policy.directives:
        if not directive.effective:
            continue
        directives.setdefault(directive.name, directive.raw_value)
    return directives


def content_security_policy_has_reporting_endpoint(header_value: str | None) -> bool:
    if header_value is None:
        return False
    parsed = parse_csp_header_value(
        header_value,
        disposition=CspDisposition.ENFORCE,
    )
    return any(
        directive.name in {"report-uri", "report-to"} and bool(directive.raw_value.strip())
        for policy in parsed.policies
        for directive in policy.directives
        if directive.effective
    )


__all__ = [
    "CspDirective",
    "CspDisposition",
    "CspParsedHeaderValue",
    "CspParseIssue",
    "CspPolicy",
    "CspToken",
    "CspTokenKind",
    "content_security_policy_directives",
    "content_security_policy_has_reporting_endpoint",
    "parse_csp_header_value",
]
