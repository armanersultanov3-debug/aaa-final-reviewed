"""Entry point for universal rules that run against the normalized config model.

Universal rules complement -- not replace -- server-specific rule packs.
Each rule is a ``check(NormalizedConfig) -> list[Finding]`` function
decorated with ``@rule(category="universal", input_kind="normalized")``.

Rules are discovered automatically via the global :data:`rule_registry.registry`.
"""

from __future__ import annotations

from webconf_audit.execution_manifest import RuleExecutionRecorder
from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.local.rule_runner_utils import executable_rule_entries, run_rule_entry
from webconf_audit.models import AnalysisIssue, Finding
from webconf_audit.rule_registry import OPT_IN_TAGS
from webconf_audit.rule_registry import registry

_UNIVERSAL_PKG = "webconf_audit.local.rules.universal"


def run_universal_rules(
    normalized: NormalizedConfig,
    *,
    issues: list[AnalysisIssue] | None = None,
    enable_policy_review: bool = False,
    execution_recorder: RuleExecutionRecorder | None = None,
) -> list[Finding]:
    """Run all universal rules against a normalized config."""
    registry.ensure_loaded(_UNIVERSAL_PKG)
    requested_opt_in_tags = ("policy-review",) if enable_policy_review else ()
    entries = registry.rules_for(
        "universal",
        include_opt_in_tags=tuple(OPT_IN_TAGS),
    )
    findings: list[Finding] = []
    for entry in executable_rule_entries(
        entries,
        requested_opt_in_tags=requested_opt_in_tags,
        execution_recorder=execution_recorder,
    ):
        findings.extend(
            run_rule_entry(
                entry,
                issues=issues,
                invoke=lambda entry=entry: entry.fn(normalized),
                execution_recorder=execution_recorder,
            )
        )
    return findings


__all__ = ["run_universal_rules"]
