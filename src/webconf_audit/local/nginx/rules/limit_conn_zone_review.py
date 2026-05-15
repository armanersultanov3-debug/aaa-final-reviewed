"""nginx.limit_conn_zone_review -- policy-review rule.

Surfaces every ``limit_conn_zone`` directive together with the
configured connection limit on the matching ``limit_conn`` directives
so operators can review whether the chosen concurrent-connection cap
fits the deployment. The right limit depends on application context
(per-user app vs. shared backend) which the scanner cannot infer.

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

RULE_ID = "nginx.limit_conn_zone_review"


@rule(
    rule_id=RULE_ID,
    title="limit_conn_zone connection limit needs operator review",
    severity="info",
    description=(
        "limit_conn_zone defines a connection-tracking pool. The matching "
        "limit_conn cap depends on the expected per-client concurrency "
        "and cannot be judged without knowing the application."
    ),
    recommendation=(
        "Review the configured per-zone limit against the expected "
        "client concurrency and document or adjust as needed."
    ),
    category="local",
    server_type="nginx",
    tags=("policy-review", "rate-limit"),
    order=282,
)
def find_limit_conn_zone_review(config_ast: ConfigAst) -> list[Finding]:
    caps_by_zone: dict[str, list[str]] = {}
    for limit_conn in iter_directives(config_ast, "limit_conn"):
        if len(limit_conn.args) >= 2:
            zone, cap = limit_conn.args[0], limit_conn.args[1]
            caps_by_zone.setdefault(zone, []).append(cap)

    findings: list[Finding] = []
    for directive in iter_directives(config_ast, "limit_conn_zone"):
        zone_name = find_zone_name(directive.args)
        if zone_name is None:
            continue
        caps = caps_by_zone.get(zone_name, [])
        if not caps:
            cap_display = "no matching limit_conn directive found"
        elif len(caps) == 1:
            cap_display = f"limit_conn cap={caps[0]}"
        else:
            cap_display = f"limit_conn caps={', '.join(caps)}"

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=(
                    f"limit_conn_zone '{zone_name}' ({cap_display}) "
                    "needs operator review"
                ),
                severity="info",
                description=(
                    f"limit_conn_zone '{zone_name}' is defined here; "
                    f"{cap_display}. Review whether the per-client "
                    "connection cap fits the expected workload."
                ),
                recommendation=(
                    "Confirm the configured per-zone limit_conn cap "
                    "matches the application's expected concurrency, or "
                    "adjust if it does not match the workload."
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


__all__ = ["find_limit_conn_zone_review"]
