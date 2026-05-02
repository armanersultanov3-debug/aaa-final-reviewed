from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheDirectiveNode

BUILTIN_LOG_FORMATS = frozenset({"common", "combined", "referer", "agent"})
CUSTOM_LOG_OPTION_PREFIXES = ("env=", "expr=")


def defined_log_format_name(directive: ApacheDirectiveNode) -> str | None:
    if len(directive.args) < 2:
        return None
    return directive.args[-1]


def defined_log_format_text(directive: ApacheDirectiveNode) -> str:
    if len(directive.args) <= 2:
        return directive.args[0] if directive.args else ""
    return " ".join(directive.args[:-1])


def referenced_log_format_name(directive: ApacheDirectiveNode) -> str | None:
    if len(directive.args) < 2:
        return None
    if directive.args[0].lower() == "off":
        return None

    candidate = directive.args[1]
    if is_custom_log_option(candidate):
        return None
    if candidate.lower() in BUILTIN_LOG_FORMATS:
        return None
    if "%" in candidate:
        return None
    return candidate


def is_custom_log_option(arg: str) -> bool:
    lowered = arg.lower()
    return any(lowered.startswith(prefix) for prefix in CUSTOM_LOG_OPTION_PREFIXES)


__all__ = [
    "BUILTIN_LOG_FORMATS",
    "CUSTOM_LOG_OPTION_PREFIXES",
    "defined_log_format_name",
    "defined_log_format_text",
    "is_custom_log_option",
    "referenced_log_format_name",
]
