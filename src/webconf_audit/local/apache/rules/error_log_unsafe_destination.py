from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.local.apache.rules._block_policy_utils import iter_directives
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.error_log_unsafe_destination"


@rule(
    rule_id=RULE_ID,
    title="ErrorLog destination is unsafe",
    severity="low",
    description="Apache ErrorLog discards error events or has no destination.",
    recommendation="Write ErrorLog to a real file or managed logging sink.",
    category="local",
    server_type="apache",
    order=345,
)
def find_error_log_unsafe_destination(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for directive in iter_directives(config_ast.nodes, "errorlog"):
        if not _is_unsafe_error_log_destination(directive):
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="ErrorLog destination is unsafe",
                severity="low",
                description=(
                    "Apache ErrorLog points to /dev/null or omits a destination, "
                    "so server error events may be discarded."
                ),
                recommendation="Set ErrorLog to a real file or managed logging sink.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


def _is_unsafe_error_log_destination(directive: ApacheDirectiveNode) -> bool:
    if not directive.args:
        return True
    return directive.args[0].lower() == "/dev/null"


__all__ = ["find_error_log_unsafe_destination"]
