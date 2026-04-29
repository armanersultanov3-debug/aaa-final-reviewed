from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._limit_utils import (
    iter_directives,
    make_finding,
    parse_positive_integer,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.limit_conn_invalid_limit"


@rule(
    rule_id=RULE_ID,
    title="Invalid limit_conn connection limit",
    severity="low",
    description="'limit_conn' does not define a positive numeric connection limit.",
    recommendation="Set 'limit_conn <zone> <positive-number>' for each enforced connection limit.",
    category="local",
    server_type="nginx",
    order=249,
)
def find_limit_conn_invalid_limit(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive in iter_directives(config_ast, "limit_conn"):
        if len(directive.args) < 2 or parse_positive_integer(directive.args[1]) is None:
            findings.append(
                make_finding(
                    rule_id=RULE_ID,
                    title="Invalid limit_conn connection limit",
                    description="'limit_conn' does not define a positive numeric connection limit.",
                    recommendation=(
                        "Set 'limit_conn <zone> <positive-number>' for each enforced "
                        "connection limit."
                    ),
                    directive=directive,
                )
            )

    return findings


__all__ = ["find_limit_conn_invalid_limit"]
