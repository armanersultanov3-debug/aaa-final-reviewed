"""nginx.limit_req_zone_rate_review -- policy-review rule.

Surfaces every defined ``limit_req_zone`` with its configured rate so an
operator can review whether the chosen value is appropriate for the
expected workload (internal admin panel vs. public API vs. health check
endpoint). The right rate depends on application context that the
scanner cannot infer.

Opt-in: only runs when ``--enable-policy-review`` is set on the CLI.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._limit_utils import (
    find_zone_name,
    iter_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.limit_req_zone_rate_review"


@rule(
    rule_id=RULE_ID,
    title="limit_req_zone rate value needs operator review",
    severity="info",
    description=(
        "limit_req_zone defines a request rate. The right value depends "
        "on application context (admin panel, public API, health check) "
        "and cannot be judged without knowing the workload."
    ),
    recommendation=(
        "Review the configured rate against the application's expected "
        "traffic profile. Document the chosen value in your deployment "
        "policy or adjust if it does not match the workload."
    ),
    category="local",
    server_type="nginx",
    tags=("policy-review", "rate-limit"),
    order=281,
)
def find_limit_req_zone_rate_review(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for directive in iter_directives(config_ast, "limit_req_zone"):
        zone_name = find_zone_name(directive.args)
        rate_arg = next(
            (arg for arg in directive.args if arg.startswith("rate=")),
            None,
        )
        if zone_name is None or rate_arg is None:
            continue
        rate_value = rate_arg.removeprefix("rate=")
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=f"limit_req_zone '{zone_name}' rate={rate_value} needs operator review",
                severity="info",
                description=(
                    f"limit_req_zone '{zone_name}' defines rate={rate_value}. "
                    "Decide whether this matches the application's expected "
                    "traffic profile."
                ),
                recommendation=(
                    "Review the configured rate against expected traffic. "
                    "Document the choice or adjust if it does not match the workload."
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


__all__ = ["find_limit_req_zone_rate_review"]
