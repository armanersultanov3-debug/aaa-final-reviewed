from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.local.apache.rules._block_policy_utils import iter_directives
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.log_level_too_restrictive"
_TOO_RESTRICTIVE_LEVELS = frozenset({"emerg", "alert", "crit", "error"})


@rule(
    rule_id=RULE_ID,
    title="LogLevel is too restrictive",
    severity="low",
    description="Apache LogLevel suppresses operational events needed for audit trails.",
    recommendation="Use at least warn, notice, or info verbosity for error logging.",
    category="local",
    server_type="apache",
    order=346,
)
def find_log_level_too_restrictive(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for directive in iter_directives(config_ast.nodes, "loglevel"):
        restrictive_levels = sorted(
            level
            for level in _configured_levels(directive)
            if level in _TOO_RESTRICTIVE_LEVELS
        )
        if not restrictive_levels:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="LogLevel is too restrictive",
                severity="low",
                description=(
                    "Apache LogLevel suppresses audit-relevant events: "
                    + ", ".join(restrictive_levels)
                ),
                recommendation="Use at least warn, notice, or info verbosity.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


def _configured_levels(directive: ApacheDirectiveNode) -> set[str]:
    levels: set[str] = set()
    for arg in directive.args:
        token = arg.lower()
        if ":" in token:
            token = token.rsplit(":", 1)[1]
        levels.add(token)
    return levels


__all__ = ["find_log_level_too_restrictive"]
