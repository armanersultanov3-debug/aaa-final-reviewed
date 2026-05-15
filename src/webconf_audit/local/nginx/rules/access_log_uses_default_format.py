"""nginx.access_log_uses_default_format -- policy-review rule.

Surfaces ``access_log`` directives that rely on Nginx's built-in
``combined`` format (either implicit, via no format argument, or
explicit) so the operator can decide whether their SIEM / log pipeline
needs a richer JSON or extended format.

Opt-in: only runs when ``--enable-policy-review`` is set on the CLI.
The right answer depends on organisation logging policy (Loki, ELK,
Splunk, plain file retention), so we surface the configured choice
rather than flagging it as a defect.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.access_log_uses_default_format"
_ACCESS_LOG_OPTION_PREFIXES = ("buffer=", "flush=", "gzip=", "if=")
_BUILTIN_LOG_FORMATS = frozenset({"combined", "compatible"})


@rule(
    rule_id=RULE_ID,
    title="access_log uses the built-in default format",
    severity="info",
    description=(
        "access_log writes records using Nginx's built-in default "
        "(combined) format. The operator should decide whether this "
        "matches their logging / SIEM / retention policy."
    ),
    recommendation=(
        "If your SIEM or audit pipeline requires JSON or specific "
        "fields, define a named log_format (with request-id, user-agent, "
        "TLS, upstream timing, etc.) and reference it from access_log. "
        "Otherwise mark this finding as accepted policy."
    ),
    category="local",
    server_type="nginx",
    tags=("policy-review", "logging"),
    order=280,
)
def find_access_log_uses_default_format(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, DirectiveNode):
            continue
        if node.name != "access_log":
            continue
        if not node.args:
            continue
        if node.args[0].lower() == "off":
            continue
        format_name = _referenced_format(node)
        if format_name is not None and format_name not in _BUILTIN_LOG_FORMATS:
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="access_log uses the built-in default format",
                severity="info",
                description=(
                    "access_log writes records using Nginx's built-in default "
                    "(combined) format. The operator should decide whether "
                    "this matches their logging / SIEM / retention policy."
                ),
                recommendation=(
                    "If your SIEM or audit pipeline requires JSON or specific "
                    "fields, define a named log_format and reference it from "
                    "access_log. Otherwise mark this finding as accepted policy."
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


def _referenced_format(directive: DirectiveNode) -> str | None:
    """Return the format-name arg of ``access_log``, or ``None`` if implicit."""
    if len(directive.args) < 2:
        return None
    candidate = directive.args[1]
    if _is_access_log_option(candidate):
        return None
    return candidate


def _is_access_log_option(arg: str) -> bool:
    lowered = arg.lower()
    return lowered == "gzip" or any(
        lowered.startswith(prefix) for prefix in _ACCESS_LOG_OPTION_PREFIXES
    )


__all__ = ["find_access_log_uses_default_format"]
