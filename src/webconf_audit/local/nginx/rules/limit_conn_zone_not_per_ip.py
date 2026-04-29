from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._limit_utils import (
    PER_IP_KEYS,
    is_per_ip_key,
    iter_directives,
    make_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.limit_conn_zone_not_per_ip"


@rule(
    rule_id=RULE_ID,
    title="limit_conn_zone is not keyed by client IP",
    severity="low",
    description="'limit_conn_zone' does not use a client IP address variable as its key.",
    recommendation=(
        "Key connection limits by '$binary_remote_addr' or '$remote_addr' so the "
        "limit applies per client IP address."
    ),
    category="local",
    server_type="nginx",
    order=250,
)
def find_limit_conn_zone_not_per_ip(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive in iter_directives(config_ast, "limit_conn_zone"):
        if is_per_ip_key(directive.args):
            continue
        findings.append(
            make_finding(
                rule_id=RULE_ID,
                title="limit_conn_zone is not keyed by client IP",
                description="'limit_conn_zone' does not use a client IP address variable as its key.",
                recommendation=(
                    "Key connection limits by "
                    f"{', '.join(sorted(PER_IP_KEYS))} so the limit applies per client IP address."
                ),
                directive=directive,
            )
        )

    return findings


__all__ = ["find_limit_conn_zone_not_per_ip"]
