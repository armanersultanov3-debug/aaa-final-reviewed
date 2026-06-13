"""Versioned rule-execution manifest models and helpers."""

from __future__ import annotations

from collections.abc import Iterable
import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from webconf_audit.coverage_models import RuleIdentifier
from webconf_audit.rule_registry import RuleMeta, RuleRegistry

NonEmptyText = StringConstraints(strip_whitespace=True, min_length=1, max_length=4096)
RegistryRevision = StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
SkippedReason = Literal[
    "mode-incompatible",
    "server-incompatible",
    "input-unavailable",
    "opt-in-not-selected",
    "prerequisite-failed",
]
ExecutionState = Literal["completed", "skipped", "failed"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionManifestIssue(_StrictModel):
    code: Annotated[str, NonEmptyText]
    message: Annotated[str, NonEmptyText]
    rule_id: str | None = None


class RuleSelection(_StrictModel):
    registry_revision: Annotated[str, RegistryRevision]
    selected_rule_ids: tuple[RuleIdentifier, ...] = Field(default=(), max_length=4096)


class SkippedRule(_StrictModel):
    rule_id: RuleIdentifier
    reason: SkippedReason


class FailedRule(_StrictModel):
    rule_id: RuleIdentifier
    issue_code: Annotated[str, NonEmptyText]
    stage: Annotated[str, NonEmptyText]


class RuleExecutionManifest(_StrictModel):
    schema_version: Literal[1] = 1
    registry_revision: Annotated[str, RegistryRevision]
    selected_rule_ids: tuple[RuleIdentifier, ...] = Field(default=(), max_length=4096)
    completed_rule_ids: tuple[RuleIdentifier, ...] = Field(default=(), max_length=4096)
    skipped_rules: tuple[SkippedRule, ...] = Field(default=(), max_length=4096)
    failed_rules: tuple[FailedRule, ...] = Field(default=(), max_length=4096)

    @model_validator(mode="after")
    def validate_terminal_sets(self) -> "RuleExecutionManifest":
        _ensure_unique(
            self.selected_rule_ids,
            code="execution_manifest_overlap",
            message="selected_rule_ids cannot contain duplicates.",
        )
        _ensure_unique(
            self.completed_rule_ids,
            code="execution_manifest_overlap",
            message="completed_rule_ids cannot contain duplicates.",
        )
        skipped_rule_ids = tuple(entry.rule_id for entry in self.skipped_rules)
        failed_rule_ids = tuple(entry.rule_id for entry in self.failed_rules)
        _ensure_unique(
            skipped_rule_ids,
            code="execution_manifest_overlap",
            message="skipped_rules cannot contain duplicate rule_id values.",
        )
        _ensure_unique(
            failed_rule_ids,
            code="execution_manifest_overlap",
            message="failed_rules cannot contain duplicate rule_id values.",
        )

        completed = set(self.completed_rule_ids)
        skipped = set(skipped_rule_ids)
        failed = set(failed_rule_ids)
        if completed & skipped or completed & failed or skipped & failed:
            raise ExecutionManifestBuildError(
                ExecutionManifestIssue(
                    code="execution_manifest_overlap",
                    message="Rule terminal states must be mutually exclusive.",
                )
            )
        return self


class RuleExecutionEvent(_StrictModel):
    rule_id: RuleIdentifier
    state: ExecutionState
    reason: SkippedReason | None = None
    issue_code: Annotated[str, NonEmptyText] | None = None
    stage: Annotated[str, NonEmptyText] | None = None

    @model_validator(mode="after")
    def validate_payload(self) -> "RuleExecutionEvent":
        if self.state == "completed":
            if self.reason is not None or self.issue_code is not None or self.stage is not None:
                raise ValueError("Completed events cannot carry reason, issue_code, or stage.")
            return self
        if self.state == "skipped":
            if self.reason is None or self.issue_code is not None or self.stage is not None:
                raise ValueError("Skipped events require only a reason.")
            return self
        if self.issue_code is None or self.stage is None or self.reason is not None:
            raise ValueError("Failed events require issue_code and stage only.")
        return self

    @classmethod
    def completed(cls, rule_id: str) -> "RuleExecutionEvent":
        return cls(rule_id=rule_id, state="completed")

    @classmethod
    def skipped(cls, rule_id: str, *, reason: SkippedReason) -> "RuleExecutionEvent":
        return cls(rule_id=rule_id, state="skipped", reason=reason)

    @classmethod
    def failed(
        cls,
        rule_id: str,
        *,
        issue_code: str,
        stage: str,
    ) -> "RuleExecutionEvent":
        return cls(
            rule_id=rule_id,
            state="failed",
            issue_code=issue_code,
            stage=stage,
        )


class ExecutionManifestBuildError(ValueError):
    """Raised when a manifest cannot be built into a trusted state."""

    def __init__(self, issue: ExecutionManifestIssue) -> None:
        super().__init__(issue.message)
        self.issue = issue


class RuleExecutionRecorder:
    """Collect selected rules and reduce terminal events deterministically."""

    def __init__(self) -> None:
        self._selected_rule_ids: list[str] = []
        self._selected_seen: set[str] = set()
        self._terminal_events: dict[str, RuleExecutionEvent] = {}

    def select(self, rule_id: str) -> None:
        if rule_id not in self._selected_seen:
            self._selected_seen.add(rule_id)
            self._selected_rule_ids.append(rule_id)

    def select_many(self, rule_ids: Iterable[str]) -> None:
        for rule_id in rule_ids:
            self.select(rule_id)

    def completed(self, rule_id: str) -> None:
        self._record_terminal(RuleExecutionEvent.completed(rule_id))

    def skipped(self, rule_id: str, *, reason: SkippedReason) -> None:
        self._record_terminal(RuleExecutionEvent.skipped(rule_id, reason=reason))

    def failed(self, rule_id: str, *, issue_code: str, stage: str) -> None:
        self._record_terminal(
            RuleExecutionEvent.failed(
                rule_id,
                issue_code=issue_code,
                stage=stage,
            )
        )

    def selected_rule_ids(self) -> tuple[str, ...]:
        return tuple(self._selected_rule_ids)

    def events(self) -> tuple[RuleExecutionEvent, ...]:
        order = {rule_id: index for index, rule_id in enumerate(self._selected_rule_ids)}
        return tuple(
            sorted(
                self._terminal_events.values(),
                key=lambda event: (order.get(event.rule_id, len(order)), event.rule_id),
            )
        )

    def _record_terminal(self, event: RuleExecutionEvent) -> None:
        self.select(event.rule_id)
        existing = self._terminal_events.get(event.rule_id)
        if existing is None or existing == event:
            self._terminal_events[event.rule_id] = event
            return
        if event.state == "failed":
            self._terminal_events[event.rule_id] = event
            return
        if existing.state == "failed":
            return
        if event.state == "completed":
            self._terminal_events[event.rule_id] = event
            return
        if existing.state == "completed":
            return
        if existing.state == "skipped" and event.state == "skipped":
            if existing.reason is None or event.reason is None:
                return
            if event.reason < existing.reason:
                self._terminal_events[event.rule_id] = event


def build_rule_execution_manifest(
    selection: RuleSelection,
    execution_events: Iterable[RuleExecutionEvent],
) -> RuleExecutionManifest:
    """Build a deterministic terminal-state manifest from rule events."""
    _ensure_unique(
        selection.selected_rule_ids,
        code="execution_manifest_overlap",
        message="selected_rule_ids cannot contain duplicates.",
    )
    selected_set = set(selection.selected_rule_ids)
    terminal_events: dict[str, RuleExecutionEvent] = {}

    for event in execution_events:
        if event.rule_id not in selected_set:
            raise ExecutionManifestBuildError(
                ExecutionManifestIssue(
                    code="execution_manifest_overlap",
                    message=(
                        f"Rule {event.rule_id!r} produced a terminal event without "
                        "being selected."
                    ),
                    rule_id=event.rule_id,
                )
            )
        if event.rule_id in terminal_events:
            raise ExecutionManifestBuildError(
                ExecutionManifestIssue(
                    code="execution_manifest_overlap",
                    message=(
                        f"Rule {event.rule_id!r} produced overlapping terminal states."
                    ),
                    rule_id=event.rule_id,
                )
            )
        terminal_events[event.rule_id] = event

    missing = [
        rule_id
        for rule_id in selection.selected_rule_ids
        if rule_id not in terminal_events
    ]
    if missing:
        raise ExecutionManifestBuildError(
            ExecutionManifestIssue(
                code="execution_manifest_incomplete",
                message=(
                    "Selected rules are missing terminal events: "
                    + ", ".join(missing)
                ),
                rule_id=missing[0],
            )
        )

    completed_rule_ids = tuple(
        rule_id
        for rule_id in selection.selected_rule_ids
        if terminal_events[rule_id].state == "completed"
    )
    skipped_rules = tuple(
        SkippedRule(
            rule_id=rule_id,
            reason=_require_skipped_reason(terminal_events[rule_id]),
        )
        for rule_id in selection.selected_rule_ids
        if terminal_events[rule_id].state == "skipped"
    )
    failed_rules = tuple(
        FailedRule(
            rule_id=rule_id,
            issue_code=_require_issue_code(terminal_events[rule_id]),
            stage=_require_stage(terminal_events[rule_id]),
        )
        for rule_id in selection.selected_rule_ids
        if terminal_events[rule_id].state == "failed"
    )

    return RuleExecutionManifest(
        schema_version=1,
        registry_revision=selection.registry_revision,
        selected_rule_ids=selection.selected_rule_ids,
        completed_rule_ids=completed_rule_ids,
        skipped_rules=skipped_rules,
        failed_rules=failed_rules,
    )


def registry_revision(registry: RuleRegistry) -> str:
    """Return a deterministic revision token for the current live registry."""
    payload = [
        _rule_meta_payload(meta)
        for meta in registry.list_rules()
    ]
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _rule_meta_payload(meta: RuleMeta) -> dict[str, object]:
    return {
        "rule_id": meta.rule_id,
        "title": meta.title,
        "severity": meta.severity,
        "declared_severity": meta.declared_severity,
        "description": meta.description,
        "recommendation": meta.recommendation,
        "category": meta.category,
        "server_type": meta.server_type,
        "input_kind": meta.input_kind,
        "tags": list(meta.tags),
        "condition": meta.condition,
        "order": meta.order,
        "standards": [
            {
                "standard": ref.standard,
                "reference": ref.reference,
                "url": ref.url,
                "coverage": ref.coverage,
                "note": ref.note,
                "tier": ref.tier,
                "origin": ref.origin,
                "derived_from_standard": ref.derived_from_standard,
                "derived_from_reference": ref.derived_from_reference,
            }
            for ref in meta.standards
        ],
        "standards_secondary": [
            {
                "standard": ref.standard,
                "reference": ref.reference,
                "url": ref.url,
                "coverage": ref.coverage,
                "note": ref.note,
                "tier": ref.tier,
                "origin": ref.origin,
                "derived_from_standard": ref.derived_from_standard,
                "derived_from_reference": ref.derived_from_reference,
            }
            for ref in meta.standards_secondary
        ],
    }


def _ensure_unique(
    values: tuple[str, ...],
    *,
    code: str,
    message: str,
) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ExecutionManifestBuildError(
                ExecutionManifestIssue(code=code, message=message, rule_id=value)
            )
        seen.add(value)


def _require_skipped_reason(event: RuleExecutionEvent) -> SkippedReason:
    if event.reason is None:
        raise ExecutionManifestBuildError(
            ExecutionManifestIssue(
                code="execution_manifest_overlap",
                message=f"Rule {event.rule_id!r} is skipped without a reason.",
                rule_id=event.rule_id,
            )
        )
    return event.reason


def _require_issue_code(event: RuleExecutionEvent) -> str:
    if event.issue_code is None:
        raise ExecutionManifestBuildError(
            ExecutionManifestIssue(
                code="execution_manifest_overlap",
                message=f"Rule {event.rule_id!r} failed without an issue_code.",
                rule_id=event.rule_id,
            )
        )
    return event.issue_code


def _require_stage(event: RuleExecutionEvent) -> str:
    if event.stage is None:
        raise ExecutionManifestBuildError(
            ExecutionManifestIssue(
                code="execution_manifest_overlap",
                message=f"Rule {event.rule_id!r} failed without a stage.",
                rule_id=event.rule_id,
            )
        )
    return event.stage


__all__ = [
    "ExecutionManifestBuildError",
    "ExecutionManifestIssue",
    "FailedRule",
    "RuleExecutionEvent",
    "RuleExecutionManifest",
    "RuleExecutionRecorder",
    "RuleSelection",
    "SkippedRule",
    "build_rule_execution_manifest",
    "registry_revision",
]
