"""Shared helpers for resilient local rule execution."""

from __future__ import annotations

from collections.abc import Callable

from webconf_audit.execution_manifest import RuleExecutionRecorder
from webconf_audit.models import AnalysisIssue, Finding, SourceLocation
from webconf_audit.rule_registry import OPT_IN_TAGS, RuleEntry


def executable_rule_entries(
    entries: list[RuleEntry],
    *,
    requested_opt_in_tags: tuple[str, ...],
    execution_recorder: RuleExecutionRecorder | None,
) -> list[RuleEntry]:
    """Select runnable entries while recording opt-in skips in the manifest."""
    if execution_recorder is not None:
        execution_recorder.select_many(entry.meta.rule_id for entry in entries)
    requested_tags = set(requested_opt_in_tags)
    runnable: list[RuleEntry] = []
    for entry in entries:
        opt_in_tags = set(entry.meta.tags) & OPT_IN_TAGS
        if opt_in_tags and not opt_in_tags.issubset(requested_tags):
            if execution_recorder is not None:
                execution_recorder.skipped(
                    entry.meta.rule_id,
                    reason="opt-in-not-selected",
                )
            continue
        runnable.append(entry)
    return runnable


def run_rule_entry(
    entry: RuleEntry,
    *,
    issues: list[AnalysisIssue] | None,
    invoke: Callable[[], list[Finding]],
    execution_recorder: RuleExecutionRecorder | None = None,
) -> list[Finding]:
    """Execute a rule and optionally downgrade rule crashes to analysis issues."""
    try:
        findings = invoke()
        if execution_recorder is not None:
            execution_recorder.completed(entry.meta.rule_id)
        return findings
    except Exception as exc:
        if execution_recorder is not None:
            execution_recorder.failed(
                entry.meta.rule_id,
                issue_code="rule_execution_error",
                stage=entry.meta.input_kind,
            )
        if issues is None:
            raise
        issues.append(_rule_execution_issue(entry, exc))
        return []


def _rule_execution_issue(entry: RuleEntry, exc: Exception) -> AnalysisIssue:
    return AnalysisIssue(
        code="rule_execution_error",
        level="warning",
        message=f"Rule {entry.meta.rule_id} failed during local analysis.",
        details=f"{type(exc).__name__}: {exc}",
        location=SourceLocation(
            mode="local",
            kind="check",
            target=entry.meta.rule_id,
        ),
        metadata={
            "rule_id": entry.meta.rule_id,
            "server_type": entry.meta.server_type,
            "category": entry.meta.category,
            "input_kind": entry.meta.input_kind,
            "exception_type": type(exc).__name__,
        },
    )


__all__ = ["executable_rule_entries", "run_rule_entry"]
