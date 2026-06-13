"""Entry point for local nginx rule modules.

Rules are discovered automatically via the global rule registry.
Each rule file in ``rules/nginx/`` is decorated with ``@rule(...)``
which registers it at import time.
"""

from __future__ import annotations

from webconf_audit.execution_manifest import RuleExecutionRecorder
from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.local.rule_runner_utils import executable_rule_entries, run_rule_entry
from webconf_audit.models import AnalysisIssue, Finding
from webconf_audit.rule_registry import OPT_IN_TAGS
from webconf_audit.rule_registry import registry

_NGINX_PKG = "webconf_audit.local.nginx.rules"
_REQUIRED_DIRECTIVES_BY_RULE_ID = {
    "nginx.proxy_pass_user_controlled_destination": frozenset({"proxy_pass"}),
}


def run_nginx_rules(
    config_ast: ConfigAst,
    *,
    issues: list[AnalysisIssue] | None = None,
    enable_policy_review: bool = False,
    execution_recorder: RuleExecutionRecorder | None = None,
) -> list[Finding]:
    registry.ensure_loaded(_NGINX_PKG)
    requested_opt_in_tags = ("policy-review",) if enable_policy_review else ()
    entries = registry.rules_for(
        "local",
        server_type="nginx",
        include_opt_in_tags=tuple(OPT_IN_TAGS),
    )
    directive_names = {
        node.name
        for node in iter_nodes(config_ast.nodes)
        if isinstance(node, DirectiveNode)
    }
    findings: list[Finding] = []
    for entry in executable_rule_entries(
        entries,
        requested_opt_in_tags=requested_opt_in_tags,
        execution_recorder=execution_recorder,
    ):
        if not _rule_prerequisites_satisfied(entry.meta.rule_id, directive_names):
            if execution_recorder is not None:
                execution_recorder.skipped(
                    entry.meta.rule_id,
                    reason="prerequisite-failed",
                )
            continue
        findings.extend(
            run_rule_entry(
                entry,
                issues=issues,
                invoke=lambda entry=entry: entry.fn(config_ast),
                execution_recorder=execution_recorder,
            )
        )
    return findings


def _rule_prerequisites_satisfied(
    rule_id: str,
    directive_names: set[str],
) -> bool:
    required_directives = _REQUIRED_DIRECTIVES_BY_RULE_ID.get(rule_id)
    if required_directives is None:
        return True
    return required_directives.issubset(directive_names)


__all__ = ["run_nginx_rules"]
