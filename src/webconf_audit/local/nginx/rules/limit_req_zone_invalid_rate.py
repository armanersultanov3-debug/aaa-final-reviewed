from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._limit_utils import (
    is_positive_rate,
    iter_directives,
    make_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.limit_req_zone_invalid_rate"


@rule(
    rule_id=RULE_ID,
    title="Invalid limit_req_zone rate",
    severity="low",
    description="'limit_req_zone' does not define a positive request rate.",
    recommendation="Set a positive 'rate=<number>r/s' or 'rate=<number>r/m' value.",
    category="local",
    server_type="nginx",
    order=252,
)
def find_limit_req_zone_invalid_rate(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive in iter_directives(config_ast, "limit_req_zone"):
        rate_values = [
            arg.removeprefix("rate=")
            for arg in directive.args
            if arg.startswith("rate=")
        ]
        if rate_values and is_positive_rate(rate_values[-1]):
            continue
        findings.append(
            make_finding(
                rule_id=RULE_ID,
                title="Invalid limit_req_zone rate",
                description="'limit_req_zone' does not define a positive request rate.",
                recommendation="Set a positive 'rate=<number>r/s' or 'rate=<number>r/m' value.",
                directive=directive,
            )
        )

    return findings


__all__ = ["find_limit_req_zone_invalid_rate"]
