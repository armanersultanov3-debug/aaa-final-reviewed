"""apache.limit_request_body_value_review -- policy-review rule.

Surfaces every effective ``LimitRequestBody`` value so an operator can
review whether the chosen request-body cap is appropriate for the
expected workload. The right value depends on application context (file
upload endpoints vs. JSON API vs. static-only site) which the scanner
cannot infer; existing rules already handle the "missing or unsafe-too-
high" cases, this rule complements them by surfacing the configured
value for human review.

Opt-in: only runs when ``--enable-policy-review`` is set on the CLI.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.local.apache.rules._block_policy_utils import iter_directives
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.limit_request_body_value_review"


@rule(
    rule_id=RULE_ID,
    title="LimitRequestBody value needs operator review",
    severity="info",
    description=(
        "LimitRequestBody defines a request-body cap. The right value "
        "depends on the application's upload / payload profile and "
        "cannot be judged without knowing the workload."
    ),
    recommendation=(
        "Review the configured cap against expected request payloads. "
        "Document the chosen value, or adjust if it does not match the "
        "application's upload / API profile."
    ),
    category="local",
    server_type="apache",
    tags=("policy-review", "limits"),
    order=380,
)
def find_limit_request_body_value_review(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for directive in iter_directives(config_ast.nodes, "LimitRequestBody"):
        value = _first_arg(directive)
        if value is None:
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=f"LimitRequestBody={value} needs operator review",
                severity="info",
                description=(
                    f"LimitRequestBody is set to {value} bytes in this scope. "
                    "Decide whether this matches the application's upload "
                    "and payload profile."
                ),
                recommendation=(
                    "Review the configured cap against expected request "
                    "payloads. Document the choice or adjust if it does not "
                    "match the application's upload / API profile."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )
    return findings


def _first_arg(directive: ApacheDirectiveNode) -> str | None:
    if not directive.args:
        return None
    return directive.args[0]


__all__ = ["find_limit_request_body_value_review"]
