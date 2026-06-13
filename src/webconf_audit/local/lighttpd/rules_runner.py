"""Entry point for local Lighttpd rule modules.

Rules are discovered automatically via the global rule registry.
Each rule file in ``rules/lighttpd/`` is decorated with ``@rule(...)``
which registers it at import time.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
import inspect

from webconf_audit.execution_manifest import RuleExecutionRecorder
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.rule_runner_utils import executable_rule_entries, run_rule_entry
from webconf_audit.models import AnalysisIssue, Finding
from webconf_audit.rule_registry import OPT_IN_TAGS
from webconf_audit.rule_registry import registry

_LIGHTTPD_PKG = "webconf_audit.local.lighttpd.rules"


def run_lighttpd_rules(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
    issues: list[AnalysisIssue] | None = None,
    enable_policy_review: bool = False,
    execution_recorder: RuleExecutionRecorder | None = None,
) -> list[Finding]:
    registry.ensure_loaded(_LIGHTTPD_PKG)
    requested_opt_in_tags = ("policy-review",) if enable_policy_review else ()
    entries = registry.rules_for(
        "local",
        server_type="lighttpd",
        include_opt_in_tags=tuple(OPT_IN_TAGS),
    )
    findings: list[Finding] = []

    for entry in executable_rule_entries(
        entries,
        requested_opt_in_tags=requested_opt_in_tags,
        execution_recorder=execution_recorder,
    ):
        if entry.meta.input_kind == "effective":
            if effective_config is None or merged_directives is None:
                if execution_recorder is not None:
                    execution_recorder.skipped(
                        entry.meta.rule_id,
                        reason="input-unavailable",
                    )
                continue
            findings.extend(
                run_rule_entry(
                    entry,
                    issues=issues,
                    invoke=lambda entry=entry: _run_effective_rule(
                        entry.fn,
                        config_ast,
                        effective_config=effective_config,
                        merged_directives=merged_directives,
                        request_context=request_context,
                    ),
                    execution_recorder=execution_recorder,
                )
            )
        else:
            findings.extend(
                run_rule_entry(
                    entry,
                    issues=issues,
                    invoke=lambda entry=entry: entry.fn(config_ast),
                    execution_recorder=execution_recorder,
                )
            )

    return findings


def _run_effective_rule(
    rule_fn: Callable[..., list[Finding]],
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None,
    request_context: LighttpdRequestContext | None,
) -> list[Finding]:
    kwargs = {
        "effective_config": effective_config,
        "merged_directives": merged_directives,
    }
    if _rule_accepts_request_context(rule_fn):
        kwargs["request_context"] = request_context
    return rule_fn(config_ast, **kwargs)


@lru_cache(maxsize=None)
def _rule_accepts_request_context(rule_fn: Callable[..., list[Finding]]) -> bool:
    return "request_context" in inspect.signature(rule_fn).parameters


__all__ = ["run_lighttpd_rules"]
