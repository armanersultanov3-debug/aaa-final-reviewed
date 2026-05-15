"""apache.custom_log_uses_default_format -- policy-review rule.

Surfaces ``CustomLog`` directives that reference one of Apache's
built-in formats (``common``, ``combined``, ``referer``, ``agent``) or
fall back to the server-scope default ``LogFormat`` so the operator
can decide whether their SIEM / log pipeline needs a richer custom
format. The right answer depends on organisation logging policy and
cannot be auto-judged.

Opt-in: only runs when ``--enable-policy-review`` is set on the CLI.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.local.apache.rules._block_policy_utils import iter_directives
from webconf_audit.local.apache.rules._log_policy_utils import (
    BUILTIN_LOG_FORMATS,
    is_custom_log_option,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.custom_log_uses_default_format"


@rule(
    rule_id=RULE_ID,
    title="CustomLog uses a built-in or default LogFormat",
    severity="info",
    description=(
        "CustomLog writes records using one of Apache's built-in formats "
        "(common / combined / referer / agent) or the server-scope default "
        "LogFormat. The operator should decide whether this matches their "
        "logging / SIEM / retention policy."
    ),
    recommendation=(
        "If your SIEM or audit pipeline requires JSON or specific fields "
        "(request-id, forwarded chain, TLS protocol/cipher, upstream timing), "
        "define a named LogFormat and reference it from CustomLog. "
        "Otherwise mark this finding as accepted policy."
    ),
    category="local",
    server_type="apache",
    tags=("policy-review", "logging"),
    order=378,
)
def find_custom_log_uses_default_format(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for node in iter_directives(config_ast.nodes, "CustomLog"):
        if not node.args or node.args[0].lower() == "off":
            continue
        if not _references_builtin_or_default(node):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="CustomLog uses a built-in or default LogFormat",
                severity="info",
                description=(
                    "CustomLog writes records using a built-in (common / "
                    "combined / referer / agent) or server-default format. "
                    "The operator should decide whether this matches the "
                    "logging / SIEM / retention policy."
                ),
                recommendation=(
                    "If your SIEM requires JSON or specific fields, define a "
                    "named LogFormat and reference it from CustomLog. "
                    "Otherwise mark this finding as accepted policy."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
            )
        )
    return findings


def _references_builtin_or_default(directive: ApacheDirectiveNode) -> bool:
    """Return True when CustomLog uses a built-in format or no format arg."""
    if len(directive.args) < 2:
        return True
    candidate = directive.args[1]
    if is_custom_log_option(candidate):
        return True
    if candidate.lower() in BUILTIN_LOG_FORMATS:
        return True
    return False


__all__ = ["find_custom_log_uses_default_format"]
