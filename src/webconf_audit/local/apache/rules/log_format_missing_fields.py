from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import iter_directives
from webconf_audit.local.apache.rules._log_policy_utils import (
    defined_log_format_name,
    defined_log_format_text,
    referenced_log_format_name,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.log_format_missing_fields"

_REQUIRED_FIELD_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("client address", ("%h", "%a")),
    ("remote user", ("%u",)),
    ("timestamp", ("%t", "%{", "}t")),
    ("request line", ("%r",)),
    ("status", ("%>s", "%s")),
    ("response size", ("%b", "%O")),
    ("referer", ("%{referer}i",)),
    ("user-agent", ("%{user-agent}i", "%{user_agent}i")),
)


@rule(
    rule_id=RULE_ID,
    title="LogFormat misses detailed audit fields",
    severity="low",
    description="Apache LogFormat is present but misses recommended audit fields.",
    recommendation=(
        "Include client address, remote user, timestamp, request, status, "
        "response size, referer, and user-agent fields in access logs."
    ),
    category="local",
    server_type="apache",
    order=348,
)
def find_log_format_missing_fields(config_ast: ApacheConfigAst) -> list[Finding]:
    used_formats = _used_custom_log_format_names(config_ast)
    findings: list[Finding] = []

    for directive in iter_directives(config_ast.nodes, "logformat"):
        format_name = defined_log_format_name(directive)
        if format_name is None or format_name not in used_formats:
            continue

        format_text = defined_log_format_text(directive).lower()
        missing_fields = _missing_fields(format_text)
        if not missing_fields:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="LogFormat misses detailed audit fields",
                severity="low",
                description=(
                    "Apache LogFormat misses recommended audit fields: "
                    + ", ".join(missing_fields)
                ),
                recommendation="Add the missing fields to the LogFormat used by CustomLog.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


def _used_custom_log_format_names(config_ast: ApacheConfigAst) -> set[str]:
    used: set[str] = set()
    for directive in iter_directives(config_ast.nodes, "customlog"):
        format_name = referenced_log_format_name(directive)
        if format_name is not None:
            used.add(format_name)
    return used


def _missing_fields(format_text: str) -> list[str]:
    missing: list[str] = []
    for label, markers in _REQUIRED_FIELD_GROUPS:
        if label == "timestamp":
            if "%t" in format_text or ("%{" in format_text and "}t" in format_text):
                continue
            missing.append(label)
            continue

        if not any(marker in format_text for marker in markers):
            missing.append(label)
    return missing


__all__ = ["find_log_format_missing_fields"]
