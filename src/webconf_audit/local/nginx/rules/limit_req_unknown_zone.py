from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._limit_utils import (
    defined_zone_names,
    find_zone_name,
    iter_directives,
    make_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.limit_req_unknown_zone"


@rule(
    rule_id=RULE_ID,
    title="limit_req references an undefined zone",
    severity="low",
    description="'limit_req' references a zone that is not defined by 'limit_req_zone'.",
    recommendation="Define the referenced 'limit_req_zone' or update 'limit_req zone=<name>'.",
    category="local",
    server_type="nginx",
    order=251,
)
def find_limit_req_unknown_zone(config_ast: ConfigAst) -> list[Finding]:
    zone_directives = iter_directives(config_ast, "limit_req_zone")
    if not zone_directives:
        return []

    defined_zones = defined_zone_names(config_ast, "limit_req_zone")
    findings: list[Finding] = []

    for directive in iter_directives(config_ast, "limit_req"):
        referenced_zone = find_zone_name(directive.args)
        if referenced_zone is not None and referenced_zone in defined_zones:
            continue
        findings.append(
            make_finding(
                rule_id=RULE_ID,
                title="limit_req references an undefined zone",
                description="'limit_req' references a zone that is not defined by 'limit_req_zone'.",
                recommendation="Define the referenced 'limit_req_zone' or update 'limit_req zone=<name>'.",
                directive=directive,
            )
        )

    return findings


__all__ = ["find_limit_req_unknown_zone"]
