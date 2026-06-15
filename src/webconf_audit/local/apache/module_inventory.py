from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from webconf_audit.apache_module_names import (
    module_aliases,
    normalized_module_identifier,
)
from webconf_audit.coverage_ledger import DEFAULT_LEDGER_MAX_BYTES
from webconf_audit.coverage_models import NonEmptyText, RuleIdentifier
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    explicit_module_identifiers,
    explicit_module_inventory,
    module_explicitly_loaded,
)
from webconf_audit.policy_models import (
    ApacheModulePolicy,
    ApacheUnlistedLoadedModules,
    CompletenessState,
    ModuleEvidenceState,
    ModuleExpectation,
    ModuleLinkage,
    ModulePredicateResult,
)

ApacheModuleAssessmentStatus = Literal[
    "pass",
    "fail",
    "not-applicable",
    "indeterminate",
]

_INVENTORY_KIND = "apache-module-inventory"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ApacheModuleSnapshotLoadError(ValueError):
    def __init__(self, code: str, message: str, *, path: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.path = path


class ApacheModuleRuntime(_StrictModel):
    version: NonEmptyText | None = None
    configuration_id: NonEmptyText | None = None


class ApacheModuleCompleteness(_StrictModel):
    state: CompletenessState
    basis: NonEmptyText


class ApacheModuleObservation(_StrictModel):
    name: RuleIdentifier
    state: ModuleEvidenceState
    linkage: ModuleLinkage = "unknown"
    source: NonEmptyText
    declared_name: NonEmptyText | None = None
    aliases: tuple[RuleIdentifier, ...] = Field(default=(), max_length=32)

    @model_validator(mode="before")
    @classmethod
    def normalize_observation(cls, value):
        if not isinstance(value, dict):
            raise ValueError("apache module observations must be objects.")
        raw_name = value.get("name")
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("apache module observations require a non-empty name.")
        normalized_name = normalized_module_identifier(raw_name)
        if not normalized_name:
            raise ValueError("apache module observations require a valid name.")
        aliases = tuple(
            alias
            for alias in module_aliases(raw_name)
            if "/" not in alias and "\\" not in alias
        )
        normalized = dict(value)
        normalized.setdefault("declared_name", raw_name.strip())
        normalized["name"] = normalized_name
        normalized["aliases"] = aliases
        return normalized


class ApacheModuleSnapshot(_StrictModel):
    schema_version: Literal[1] = 1
    kind: Literal[_INVENTORY_KIND] = _INVENTORY_KIND
    snapshot_id: NonEmptyText
    host: NonEmptyText
    captured_at: datetime
    environment: NonEmptyText | None = None
    apache: ApacheModuleRuntime = Field(default_factory=ApacheModuleRuntime)
    completeness: ApacheModuleCompleteness
    modules: tuple[ApacheModuleObservation, ...] = Field(default=(), max_length=4096)

    @model_validator(mode="after")
    def validate_snapshot(self) -> "ApacheModuleSnapshot":
        if self.completeness.state != "complete":
            for module in self.modules:
                if module.state == "absent":
                    raise ValueError(
                        "absent modules require completeness state 'complete'."
                    )

        deduplicated: dict[str, ApacheModuleObservation] = {}
        for module in self.modules:
            existing = deduplicated.get(module.name)
            if existing is None:
                deduplicated[module.name] = module
                continue
            if existing.state != module.state:
                raise ValueError(
                    "apache module snapshot contains conflicting state for "
                    f"{module.name!r} via aliases {existing.declared_name!r} and "
                    f"{module.declared_name!r}."
                )
            if existing.linkage != module.linkage:
                raise ValueError(
                    "apache module snapshot contains conflicting linkage for "
                    f"{module.name!r} via aliases {existing.declared_name!r} and "
                    f"{module.declared_name!r}."
                )
            if existing.source != module.source:
                raise ValueError(
                    "apache module snapshot contains conflicting provenance for "
                    f"{module.name!r} via aliases {existing.declared_name!r} and "
                    f"{module.declared_name!r}."
                )
            deduplicated[module.name] = existing.model_copy(
                update={
                    "aliases": tuple(
                        sorted(set(existing.aliases) | set(module.aliases))
                    )
                }
            )

        ordered = tuple(sorted(deduplicated.values(), key=lambda module: module.name))
        if ordered == self.modules:
            return self
        return self.model_copy(update={"modules": ordered})

    def module_map(self) -> dict[str, ApacheModuleObservation]:
        return {module.name: module for module in self.modules}


class ApacheModuleComparison(_StrictModel):
    module_name: RuleIdentifier
    aliases: tuple[RuleIdentifier, ...] = Field(default=(), max_length=32)
    snapshot_state: ModuleEvidenceState
    snapshot_linkage: ModuleLinkage
    snapshot_source: NonEmptyText
    policy_expectation: ModuleExpectation | None = None
    policy_key: RuleIdentifier | None = None
    config_visible: bool | None = None
    predicate_result: ModulePredicateResult
    reason: NonEmptyText
    limitations: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)
    related_findings: tuple[RuleIdentifier, ...] = Field(default=(), max_length=64)


class ApacheModuleEvaluation(_StrictModel):
    schema_version: Literal[1] = 1
    control_id: Literal["apache.module_inventory"] = "apache.module_inventory"
    policy_id: NonEmptyText
    snapshot_id: NonEmptyText
    benchmark_applicable: bool | None = None
    status: ApacheModuleAssessmentStatus
    summary: NonEmptyText
    inventory_complete: bool
    observations_complete: bool
    evidence_references: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)
    missing_evidence: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)
    limitations: tuple[NonEmptyText, ...] = Field(default=(), max_length=128)
    conflicting_modules: tuple[RuleIdentifier, ...] = Field(default=(), max_length=128)
    loaded_allowed_modules: tuple[RuleIdentifier, ...] = Field(default=(), max_length=128)
    loaded_unlisted_modules: tuple[RuleIdentifier, ...] = Field(default=(), max_length=128)
    comparisons: tuple[ApacheModuleComparison, ...] = Field(default=(), max_length=4096)


def load_apache_module_snapshot(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_LEDGER_MAX_BYTES,
) -> ApacheModuleSnapshot:
    snapshot_path = Path(path)
    try:
        stat = snapshot_path.stat()
    except OSError as exc:
        raise ApacheModuleSnapshotLoadError(
            "apache_module_snapshot_not_found",
            f"Apache module snapshot could not be read: {snapshot_path}",
            path=str(snapshot_path),
        ) from exc
    if stat.st_size > max_bytes:
        raise ApacheModuleSnapshotLoadError(
            "apache_module_snapshot_too_large",
            (
                "Apache module snapshot exceeds the "
                f"{max_bytes}-byte limit: {snapshot_path}"
            ),
            path=str(snapshot_path),
        )
    try:
        raw_text = snapshot_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ApacheModuleSnapshotLoadError(
            "apache_module_snapshot_invalid",
            "Apache module snapshot must be UTF-8 encoded.",
            path=str(snapshot_path),
        ) from exc
    except OSError as exc:
        raise ApacheModuleSnapshotLoadError(
            "apache_module_snapshot_not_found",
            f"Apache module snapshot could not be read: {snapshot_path}",
            path=str(snapshot_path),
        ) from exc
    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ApacheModuleSnapshotLoadError(
            "apache_module_snapshot_invalid",
            f"Apache module snapshot JSON is invalid: {exc}",
            path=str(snapshot_path),
        ) from exc
    if not isinstance(raw, dict):
        raise ApacheModuleSnapshotLoadError(
            "apache_module_snapshot_invalid",
            "Apache module snapshot root must be an object.",
            path=str(snapshot_path),
        )
    if raw.get("schema_version") != 1:
        raise ApacheModuleSnapshotLoadError(
            "apache_module_snapshot_unsupported",
            (
                "Unsupported apache module snapshot schema_version: "
                f"{raw.get('schema_version')!r}."
            ),
            path=str(snapshot_path),
        )
    if raw.get("kind") != _INVENTORY_KIND:
        raise ApacheModuleSnapshotLoadError(
            "apache_module_snapshot_invalid",
            (
                "Apache module snapshot kind must be "
                f"{_INVENTORY_KIND!r}, not {raw.get('kind')!r}."
            ),
            path=str(snapshot_path),
        )
    try:
        return ApacheModuleSnapshot.model_validate(raw)
    except ValueError as exc:
        raise ApacheModuleSnapshotLoadError(
            "apache_module_snapshot_invalid",
            f"Apache module snapshot schema is invalid: {exc}",
            path=str(snapshot_path),
        ) from exc


def evaluate_apache_modules(
    snapshot: ApacheModuleSnapshot,
    policy: ApacheModulePolicy,
    config_ast: ApacheConfigAst,
) -> ApacheModuleEvaluation:
    snapshot_modules = snapshot.module_map()
    config_visible_modules = explicit_module_inventory(config_ast)
    config_visible_identifiers = explicit_module_identifiers(config_ast)
    benchmark = policy.benchmark_scope.cis_apache_2_4_v2_3_0
    comparisons: list[ApacheModuleComparison] = []
    missing_evidence: list[str] = []
    limitations: set[str] = set()
    conflicting_modules: set[str] = set()
    loaded_allowed_modules: set[str] = set()
    loaded_unlisted_modules: set[str] = set()
    direct_violations: set[str] = set()
    unknown_modules: set[str] = set()

    if benchmark is None:
        missing_evidence.append(
            "benchmark applicability was not declared for cis_apache_2_4_v2_3_0"
        )
    if policy.unlisted_loaded_modules != "fail":
        missing_evidence.append(
            "unlisted loaded module posture must be 'fail' for a closed least-functionality conclusion"
        )
    elif benchmark is not None and not benchmark.applicable:
        rationale = benchmark.rationale or "benchmark scope marked not applicable."
        return ApacheModuleEvaluation(
            policy_id=policy.policy_id,
            snapshot_id=snapshot.snapshot_id,
            benchmark_applicable=False,
            status="not-applicable",
            summary=rationale,
            inventory_complete=snapshot.completeness.state == "complete",
            observations_complete=True,
            evidence_references=_evidence_references(snapshot),
            limitations=(),
            comparisons=(),
        )

    relevant_modules = sorted(
        set(policy.modules)
        | {
            module.name
            for module in snapshot.modules
            if module.state == "loaded"
        }
        | {
            module_name
            for module_name in config_visible_identifiers
        }
    )

    for module_name in relevant_modules:
        expectation_entry = policy.modules.get(module_name)
        config_visible = module_explicitly_loaded(config_visible_modules, module_name)
        observation = snapshot_modules.get(module_name)
        if observation is None:
            if snapshot.completeness.state == "complete":
                observation = ApacheModuleObservation(
                    name=module_name,
                    state="absent",
                    linkage="unknown",
                    source="complete-snapshot-omission",
                    declared_name=module_name,
                    aliases=(module_name,),
                )
            else:
                observation = ApacheModuleObservation(
                    name=module_name,
                    state="unknown",
                    linkage="unknown",
                    source=f"{snapshot.completeness.state}-snapshot-omission",
                    declared_name=module_name,
                    aliases=(module_name,),
                )
        reason, predicate_result = _comparison_result(
            snapshot=snapshot,
            observation=observation,
            expectation=expectation_entry.expectation if expectation_entry else None,
            config_visible=config_visible,
            unlisted_loaded_modules=policy.unlisted_loaded_modules,
        )
        comparison_limitations: list[str] = []
        if config_visible and observation.state != "loaded":
            comparison_limitations.append(
                "Config-visible LoadModule corroborates presence but does not replace the explicit snapshot."
            )
        if (
            config_visible
            and snapshot.completeness.state == "complete"
            and observation.state == "absent"
        ):
            conflicting_modules.add(module_name)
            comparison_limitations.append(
                "Complete snapshot absence conflicts with an active visible LoadModule directive."
            )
        if expectation_entry is None and observation.state == "loaded":
            loaded_unlisted_modules.add(module_name)
        if expectation_entry is not None and expectation_entry.expectation == "allowed" and observation.state == "loaded":
            loaded_allowed_modules.add(module_name)
        if predicate_result == "violated":
            direct_violations.add(module_name)
        elif predicate_result == "unknown":
            unknown_modules.add(module_name)
        limitations.update(comparison_limitations)
        comparisons.append(
            ApacheModuleComparison(
                module_name=module_name,
                aliases=observation.aliases,
                snapshot_state=observation.state,
                snapshot_linkage=observation.linkage,
                snapshot_source=observation.source,
                policy_expectation=expectation_entry.expectation if expectation_entry else None,
                policy_key=module_name if expectation_entry else None,
                config_visible=config_visible,
                predicate_result=predicate_result,
                reason=reason,
                limitations=tuple(comparison_limitations),
            )
        )

    inventory_complete = snapshot.completeness.state == "complete" and not conflicting_modules
    observations_complete = (
        inventory_complete
        and not missing_evidence
        and not unknown_modules
        and not loaded_allowed_modules
    )

    if direct_violations:
        status: ApacheModuleAssessmentStatus = "fail"
        summary = "Explicit snapshot and policy evidence show Apache module policy violations."
    elif missing_evidence or conflicting_modules or unknown_modules or loaded_allowed_modules:
        status = "indeterminate"
        summary = "Module evidence is incomplete or requires operator review before a safe conclusion."
    else:
        status = "pass"
        summary = "Explicit snapshot and module policy agree on the reviewed loaded Apache modules."

    return ApacheModuleEvaluation(
        policy_id=policy.policy_id,
        snapshot_id=snapshot.snapshot_id,
        benchmark_applicable=True,
        status=status,
        summary=summary,
        inventory_complete=inventory_complete,
        observations_complete=observations_complete and status == "pass",
        evidence_references=_evidence_references(snapshot),
        missing_evidence=tuple(sorted(set(missing_evidence))),
        limitations=tuple(sorted(limitations)),
        conflicting_modules=tuple(sorted(conflicting_modules)),
        loaded_allowed_modules=tuple(sorted(loaded_allowed_modules)),
        loaded_unlisted_modules=tuple(sorted(loaded_unlisted_modules)),
        comparisons=tuple(comparisons),
    )


def _comparison_result(
    *,
    snapshot: ApacheModuleSnapshot,
    observation: ApacheModuleObservation,
    expectation: ModuleExpectation | None,
    config_visible: bool,
    unlisted_loaded_modules: ApacheUnlistedLoadedModules,
) -> tuple[str, ModulePredicateResult]:
    if (
        config_visible
        and snapshot.completeness.state == "complete"
        and observation.state == "absent"
    ):
        return (
            "Complete snapshot absence conflicts with an active visible LoadModule directive.",
            "unknown",
        )
    if expectation == "not-applicable":
        return (
            "Module policy explicitly marks this module outside the benchmark decision set.",
            "not-applicable",
        )
    if expectation is None:
        if observation.state != "loaded":
            return (
                "No explicit policy decision was needed because the module was not observed as loaded.",
                "not-applicable",
            )
        if unlisted_loaded_modules == "fail":
            return (
                "Loaded module is unlisted and the policy uses a closed fail posture.",
                "violated",
            )
        if unlisted_loaded_modules == "indeterminate":
            return (
                "Loaded module is unlisted and the policy requires indeterminate review.",
                "unknown",
            )
        return (
            "Loaded module is unlisted but the policy explicitly allows review without proving necessity.",
            "unknown",
        )

    if expectation == "required":
        if observation.state == "loaded":
            return ("Required module is explicitly loaded in the snapshot.", "satisfied")
        if observation.state == "absent":
            return (
                "Required module is conclusively absent from the complete snapshot.",
                "violated",
            )
        return (
            "Required module could not be concluded because the snapshot is incomplete or unknown.",
            "unknown",
        )

    if expectation == "forbidden":
        if observation.state == "loaded":
            return ("Forbidden module is loaded in the explicit snapshot.", "violated")
        if observation.state == "absent":
            return ("Forbidden module is absent in the complete snapshot.", "satisfied")
        return (
            "Forbidden module could not be concluded because the snapshot is incomplete or unknown.",
            "unknown",
        )

    if expectation == "allowed":
        if observation.state == "unknown":
            return (
                "Allowed module could not be concluded because the snapshot is incomplete or unknown.",
                "unknown",
            )
        return (
            "Allowed module is reviewed operator policy evidence but does not prove least functionality.",
            "satisfied",
        )

    return ("Unsupported module expectation.", "unknown")


def _evidence_references(snapshot: ApacheModuleSnapshot) -> tuple[str, ...]:
    references = {
        f"apache-module-snapshot:{snapshot.snapshot_id}",
        f"host:{snapshot.host}",
        f"snapshot-completeness:{snapshot.completeness.state}",
    }
    if snapshot.apache.configuration_id is not None:
        references.add(f"configuration:{snapshot.apache.configuration_id}")
    return tuple(sorted(references))


__all__ = [
    "ApacheModuleComparison",
    "ApacheModuleEvaluation",
    "ApacheModuleObservation",
    "ApacheModuleSnapshot",
    "ApacheModuleSnapshotLoadError",
    "evaluate_apache_modules",
    "load_apache_module_snapshot",
]
