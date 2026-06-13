from __future__ import annotations

import pytest


def test_build_rule_execution_manifest_happy_path() -> None:
    from webconf_audit.execution_manifest import (
        RuleExecutionEvent,
        RuleExecutionManifest,
        RuleSelection,
        build_rule_execution_manifest,
    )

    manifest = build_rule_execution_manifest(
        RuleSelection(
            registry_revision="registry:test",
            selected_rule_ids=("rule.a", "rule.b", "rule.c"),
        ),
        [
            RuleExecutionEvent.completed("rule.a"),
            RuleExecutionEvent.failed(
                "rule.b",
                issue_code="rule_execution_error",
                stage="normalized",
            ),
            RuleExecutionEvent.skipped("rule.c", reason="input-unavailable"),
        ],
    )

    assert manifest == RuleExecutionManifest(
        schema_version=1,
        registry_revision="registry:test",
        selected_rule_ids=("rule.a", "rule.b", "rule.c"),
        completed_rule_ids=("rule.a",),
        skipped_rules=(
            {
                "rule_id": "rule.c",
                "reason": "input-unavailable",
            },
        ),
        failed_rules=(
            {
                "rule_id": "rule.b",
                "issue_code": "rule_execution_error",
                "stage": "normalized",
            },
        ),
    )


def test_build_rule_execution_manifest_rejects_incomplete_selection() -> None:
    from webconf_audit.execution_manifest import (
        ExecutionManifestBuildError,
        RuleExecutionEvent,
        RuleSelection,
        build_rule_execution_manifest,
    )

    with pytest.raises(ExecutionManifestBuildError) as excinfo:
        build_rule_execution_manifest(
            RuleSelection(
                registry_revision="registry:test",
                selected_rule_ids=("rule.a", "rule.b"),
            ),
            [RuleExecutionEvent.completed("rule.a")],
        )

    assert excinfo.value.issue.code == "execution_manifest_incomplete"


def test_build_rule_execution_manifest_rejects_overlap() -> None:
    from webconf_audit.execution_manifest import (
        ExecutionManifestBuildError,
        RuleExecutionEvent,
        RuleSelection,
        build_rule_execution_manifest,
    )

    with pytest.raises(ExecutionManifestBuildError) as excinfo:
        build_rule_execution_manifest(
            RuleSelection(
                registry_revision="registry:test",
                selected_rule_ids=("rule.a",),
            ),
            [
                RuleExecutionEvent.completed("rule.a"),
                RuleExecutionEvent.skipped("rule.a", reason="prerequisite-failed"),
            ],
        )

    assert excinfo.value.issue.code == "execution_manifest_overlap"


def test_registry_revision_is_independent_of_rule_iteration_order() -> None:
    from webconf_audit.execution_manifest import registry_revision
    from webconf_audit.rule_registry import RuleMeta

    metas = [
        RuleMeta(
            rule_id="rule.b",
            title="Rule B",
            severity="low",
            description="B",
            recommendation="Fix B",
            category="local",
            order=20,
        ),
        RuleMeta(
            rule_id="rule.a",
            title="Rule A",
            severity="medium",
            description="A",
            recommendation="Fix A",
            category="external",
            input_kind="probe",
            order=10,
        ),
    ]

    class _Registry:
        def __init__(self, rule_metas):
            self._rule_metas = rule_metas

        def list_rules(self):
            return list(self._rule_metas)

    assert registry_revision(_Registry(metas)) == registry_revision(
        _Registry(list(reversed(metas)))
    )
