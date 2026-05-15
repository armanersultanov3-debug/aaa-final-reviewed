"""Entry point for local nginx rule modules.

Rules are discovered automatically via the global rule registry.
Each rule file in ``rules/nginx/`` is decorated with ``@rule(...)``
which registers it at import time.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.rule_runner_utils import run_rule_entry
from webconf_audit.models import AnalysisIssue, Finding
from webconf_audit.rule_registry import registry

_NGINX_PKG = "webconf_audit.local.nginx.rules"


def run_nginx_rules(
    config_ast: ConfigAst,
    *,
    issues: list[AnalysisIssue] | None = None,
    enable_policy_review: bool = False,
) -> list[Finding]:
    registry.ensure_loaded(_NGINX_PKG)
    include_opt_in = ("policy-review",) if enable_policy_review else ()
    findings: list[Finding] = []
    for entry in registry.rules_for(
        "local",
        server_type="nginx",
        include_opt_in_tags=include_opt_in,
    ):
        findings.extend(
            run_rule_entry(
                entry,
                issues=issues,
                invoke=lambda entry=entry: entry.fn(config_ast),
            )
        )
    return findings


__all__ = ["run_nginx_rules"]
