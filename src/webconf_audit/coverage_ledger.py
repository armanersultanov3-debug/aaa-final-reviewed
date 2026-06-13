"""Load, validate, summarize, and render control-source coverage claims."""

from __future__ import annotations

from collections import Counter
from decimal import Decimal, ROUND_HALF_UP
from importlib.resources import files
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from pydantic import ValidationError
import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver
from yaml.tokens import AliasToken, AnchorToken, ScalarToken, TagToken

from webconf_audit.coverage_models import (
    CoverageItem,
    CoverageLedger,
    CoverageLedgerIssue,
    CoverageSource,
    RegistryReferenceClaim,
    SourceCoverageSummary,
)
from webconf_audit.rule_registry import RuleRegistry
from webconf_audit.standard_catalog import (
    find_standard_source,
    is_valid_ledger_reference,
)

DEFAULT_LEDGER_MAX_BYTES = 2 * 1024 * 1024
_PACKAGED_LEDGER = "control_source_coverage.yml"
_APPLICABLE_STATUSES = ("full", "partial", "policy-review", "uncovered")


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class CoverageLedgerLoadError(ValueError):
    """Raised when a coverage ledger cannot be loaded into a trusted model."""

    def __init__(self, issue: CoverageLedgerIssue) -> None:
        super().__init__(issue.message)
        self.issue = issue


def load_coverage_ledger(
    path: Path | None = None,
    *,
    max_bytes: int = DEFAULT_LEDGER_MAX_BYTES,
) -> CoverageLedger:
    """Load the packaged ledger or a bounded local YAML file."""
    if path is None:
        resource = files("webconf_audit.data").joinpath(_PACKAGED_LEDGER)
        try:
            payload = resource.read_bytes()
        except FileNotFoundError as exc:
            raise _load_error(
                "ledger_file_not_found",
                f"Packaged coverage ledger {_PACKAGED_LEDGER!r} was not found.",
            ) from exc
        display_path = f"package:{_PACKAGED_LEDGER}"
    else:
        display_path = str(path)
        try:
            size = path.stat().st_size
        except FileNotFoundError as exc:
            raise _load_error(
                "ledger_file_not_found",
                f"Coverage ledger was not found: {path}",
                path=display_path,
            ) from exc
        if size > max_bytes:
            raise _load_error(
                "ledger_file_too_large",
                f"Coverage ledger exceeds the {max_bytes}-byte limit: {path}",
                path=display_path,
            )
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise _load_error(
                "ledger_file_not_found",
                f"Coverage ledger could not be read: {path}",
                path=display_path,
            ) from exc

    if len(payload) > max_bytes:
        raise _load_error(
            "ledger_file_too_large",
            f"Coverage ledger exceeds the {max_bytes}-byte limit: {display_path}",
            path=display_path,
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _load_error(
            "ledger_yaml_invalid",
            "Coverage ledger must be UTF-8 encoded.",
            path=display_path,
        ) from exc
    _reject_unsafe_yaml(text, display_path)
    try:
        raw = yaml.load(text, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise _load_error(
            "ledger_yaml_invalid",
            f"Coverage ledger YAML is invalid: {exc}",
            path=display_path,
        ) from exc
    if not isinstance(raw, dict):
        raise _load_error(
            "ledger_schema_invalid",
            "Coverage ledger root must be a mapping.",
            path=display_path,
        )
    _reject_non_string_keys(raw, display_path)
    if raw.get("schema_version") != 1:
        raise _load_error(
            "ledger_schema_unsupported",
            f"Unsupported coverage ledger schema_version: {raw.get('schema_version')!r}.",
            path=display_path,
        )
    try:
        return CoverageLedger.model_validate(raw)
    except ValidationError as exc:
        raise _load_error(
            "ledger_schema_invalid",
            f"Coverage ledger schema is invalid: {exc}",
            path=display_path,
        ) from exc


def validate_coverage_ledger(
    ledger: CoverageLedger,
    registry: RuleRegistry,
) -> tuple[CoverageLedgerIssue, ...]:
    """Return all safe-to-accumulate ledger integrity defects."""
    issues: list[CoverageLedgerIssue] = []
    seen_sources: set[str] = set()
    seen_items: set[str] = set()
    for source in ledger.sources:
        if source.source_id in seen_sources:
            issues.append(
                _issue(
                    "duplicate_source_id",
                    f"Duplicate source_id {source.source_id!r}.",
                    source=source,
                )
            )
        seen_sources.add(source.source_id)
        for item in source.items:
            if item.item_id in seen_items:
                issues.append(
                    _issue(
                        "duplicate_item_id",
                        f"Duplicate item_id {item.item_id!r}.",
                        source=source,
                        item=item,
                    )
                )
            seen_items.add(item.item_id)
        issues.extend(_validate_source(source, registry))
    return tuple(sorted(set(issues), key=_issue_sort_key))


def summarize_coverage(
    ledger: CoverageLedger,
) -> tuple[SourceCoverageSummary, ...]:
    """Compute deterministic source totals from item statuses."""
    return tuple(_summarize_source(source) for source in ledger.sources)


def render_coverage_json(ledger: CoverageLedger) -> str:
    """Render the canonical ledger as deterministic JSON."""
    return (
        json.dumps(
            ledger.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_coverage_markdown(ledger: CoverageLedger) -> str:
    """Render the stable human-facing tracker from the canonical ledger."""
    summaries = summarize_coverage(ledger)
    lines = [
        "<!-- Generated from "
        "src/webconf_audit/data/control_source_coverage.yml; "
        "refresh with `webconf-audit coverage export --format markdown "
        "--output docs/control-source-coverage-tracker.md --force`. -->",
        "# Control Source Coverage Tracker",
        "",
        "This generated view summarizes scanner-evidence coverage within the "
        "declared project scope. It does not certify compliance with any source.",
        "",
        "The denominator is `full + partial + policy-review + uncovered`. "
        "Only `full` items enter the numerator.",
        "",
        "## Snapshot Summary",
        "",
        "| Control source | Applicable | Full | Partial | `policy-review` | "
        "Uncovered | Full coverage |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for summary in summaries:
        lines.append(
            f"| {_markdown_cell(summary.title)} | {summary.applicable} | "
            f"{summary.full} | {summary.partial} | {summary.policy_review} | "
            f"{summary.uncovered} | {summary.full_percent:.1f}% |"
        )
    lines.extend(
        [
            "",
            "## Status Vocabulary",
            "",
            "| Status | Meaning |",
            "| --- | --- |",
            "| `full` | All mandatory subclaims are implemented for the documented scope. |",
            "| `partial` | A real narrower signal is implemented, with explicit limitations. |",
            "| `policy-review` | Evidence is surfaced for operator judgment. |",
            "| `uncovered` | The item is applicable but has no adequate evidence path. |",
            "| `excluded` | The item is outside the denominator for a documented boundary. |",
        ]
    )
    for source, summary in zip(ledger.sources, summaries, strict=True):
        lines.extend(
            [
                "",
                f"## {_markdown_cell(source.title)}",
                "",
                _markdown_cell(source.scope_note),
                "",
                f"Applicable count: {summary.applicable}. Full count: "
                f"{summary.full}. Partial count: {summary.partial}. "
                f"`policy-review` count: {summary.policy_review}. "
                f"Uncovered count: {summary.uncovered}. Excluded count: "
                f"{summary.excluded}.",
                "",
                "| Counted item | Status | Current basis / limitations |",
                "| --- | --- | --- |",
            ]
        )
        for item in source.items:
            references = "; ".join(
                (
                    reference.reference
                    if not reference.grouped_references
                    else (
                        f"{reference.reference} "
                        f"({', '.join(reference.grouped_references)})"
                    )
                )
                for reference in item.references
            )
            label = f"{references} {item.title}".strip()
            basis = item.evidence.rationale
            if item.evidence.limitations:
                basis += " Limitations: " + "; ".join(item.evidence.limitations)
            if item.exclusion is not None:
                basis += (
                    f" Exclusion: {item.exclusion.reason} "
                    f"Boundary: {item.exclusion.boundary}"
                )
            lines.append(
                f"| {_markdown_cell(label)} | `{item.status}` | "
                f"{_markdown_cell(basis)} |"
            )
    return "\n".join(lines) + "\n"


def check_coverage_documentation(
    ledger: CoverageLedger,
    tracker_path: Path,
    benchmark_path: Path,
) -> tuple[CoverageLedgerIssue, ...]:
    """Compare checked-in human views with deterministic ledger output."""
    issues: list[CoverageLedgerIssue] = []
    expected_tracker = render_coverage_markdown(ledger)
    try:
        actual_tracker = tracker_path.read_text(encoding="utf-8")
    except OSError:
        actual_tracker = ""
    if actual_tracker != expected_tracker:
        issues.append(
            CoverageLedgerIssue(
                code="tracker_render_drift",
                message=f"{tracker_path} does not match the canonical ledger render.",
                path=str(tracker_path),
            )
        )

    expected_summaries = {
        summary.title: (
            summary.applicable,
            summary.full,
            summary.partial,
            summary.policy_review,
            summary.uncovered,
            f"{summary.full_percent:.1f}%",
        )
        for summary in summarize_coverage(ledger)
    }
    actual_summaries = _read_markdown_summary(benchmark_path)
    for title, expected in expected_summaries.items():
        if actual_summaries.get(title) != expected:
            issues.append(
                CoverageLedgerIssue(
                    code="benchmark_summary_drift",
                    message=(
                        f"{benchmark_path} summary for {title!r} does not match "
                        f"the canonical ledger: expected {expected}, got "
                        f"{actual_summaries.get(title)!r}."
                    ),
                    source_id=_source_id_for_title(ledger, title),
                    path=str(benchmark_path),
                )
            )
    for title in sorted(actual_summaries.keys() - expected_summaries.keys()):
        issues.append(
            CoverageLedgerIssue(
                code="benchmark_summary_drift",
                message=(
                    f"{benchmark_path} contains an unexpected coverage summary "
                    f"for {title!r}."
                ),
                source_id=_source_id_for_title(ledger, title),
                path=str(benchmark_path),
            )
        )
    return tuple(sorted(set(issues), key=_issue_sort_key))


def write_coverage_output(
    path: Path,
    content: str,
    *,
    force: bool = False,
) -> CoverageLedgerIssue | None:
    """Publish an export atomically without following an output symlink."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            return CoverageLedgerIssue(
                code="output_write_failed",
                message=f"Refusing to replace symlink output path: {path}",
                path=str(path),
            )
        if path.exists() and not force:
            return CoverageLedgerIssue(
                code="output_exists",
                message=f"Output already exists: {path}",
                path=str(path),
            )
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            if force:
                os.replace(temporary, path)
            else:
                os.link(temporary, path)
                temporary.unlink()
        finally:
            if temporary.exists():
                temporary.unlink()
    except FileExistsError:
        return CoverageLedgerIssue(
            code="output_exists",
            message=f"Output already exists: {path}",
            path=str(path),
        )
    except OSError as exc:
        return CoverageLedgerIssue(
            code="output_write_failed",
            message=f"Could not write coverage output {path}: {exc}",
            path=str(path),
        )
    return None


def _validate_source(
    source: CoverageSource,
    registry: RuleRegistry,
) -> list[CoverageLedgerIssue]:
    issues: list[CoverageLedgerIssue] = []
    catalog_source = find_standard_source(source.source_id)
    if catalog_source is None:
        issues.append(
            _issue(
                "unknown_source_reference",
                f"Unknown coverage source {source.source_id!r}.",
                source=source,
            )
        )
    else:
        if (
            source.title != catalog_source.title
            or source.version != catalog_source.version
            or str(source.authority_url).rstrip("/")
            != catalog_source.authority_url.rstrip("/")
        ):
            issues.append(
                _issue(
                    "unknown_source_reference",
                    "Coverage source metadata does not match the source catalog.",
                    source=source,
                )
            )
    for item in source.items:
        issues.extend(_validate_item(source, item, registry))

    actual = _summarize_source(source)
    expected = source.expected_summary
    count_fields = (
        "applicable",
        "full",
        "partial",
        "policy_review",
        "uncovered",
        "excluded",
    )
    mismatches = [
        field
        for field in count_fields
        if getattr(actual, field) != getattr(expected, field)
    ]
    if mismatches:
        issues.append(
            _issue(
                "summary_count_mismatch",
                "Expected summary counts do not match items: "
                + ", ".join(
                    f"{field}={getattr(expected, field)} "
                    f"(computed {getattr(actual, field)})"
                    for field in mismatches
                ),
                source=source,
            )
        )
    if actual.full_percent != expected.full_percent:
        issues.append(
            _issue(
                "summary_percentage_mismatch",
                f"Expected full_percent {expected.full_percent} does not match "
                f"computed {actual.full_percent}.",
                source=source,
            )
        )
    return issues


def _validate_item(
    source: CoverageSource,
    item: CoverageItem,
    registry: RuleRegistry,
) -> list[CoverageLedgerIssue]:
    issues: list[CoverageLedgerIssue] = []
    if item.status == "excluded":
        if item.applicability != "excluded":
            issues.append(
                _issue(
                    "invalid_status_applicability",
                    "Excluded status requires excluded applicability.",
                    source=source,
                    item=item,
                )
            )
        if item.exclusion is None:
            issues.append(
                _issue(
                    "missing_exclusion_reason",
                    "Excluded item requires an exclusion reason and boundary.",
                    source=source,
                    item=item,
                )
            )
    else:
        if item.applicability != "applicable":
            issues.append(
                _issue(
                    "invalid_status_applicability",
                    f"Status {item.status!r} requires applicable applicability.",
                    source=source,
                    item=item,
                )
            )
        if item.exclusion is not None:
            issues.append(
                _issue(
                    "unexpected_exclusion",
                    "Applicable item cannot include exclusion metadata.",
                    source=source,
                    item=item,
                )
            )

    for reference in item.references:
        if not is_valid_ledger_reference(
            source.source_id,
            reference.standard,
            reference.reference,
        ):
            issues.append(
                _issue(
                    "unknown_source_reference",
                    f"Unknown source reference {reference.standard!r} "
                    f"{reference.reference!r}.",
                    source=source,
                    item=item,
                )
            )
        for grouped_reference in reference.grouped_references:
            if not is_valid_ledger_reference(
                source.source_id,
                reference.standard,
                grouped_reference,
            ):
                issues.append(
                    _issue(
                        "unknown_source_reference",
                        f"Unknown grouped source reference "
                        f"{reference.standard!r} {grouped_reference!r}.",
                        source=source,
                        item=item,
                    )
                )

    evidence = item.evidence
    seen_claims: set[tuple[str, str, str, str, str]] = set()
    for rule_id in evidence.rule_ids:
        if registry.get_meta(rule_id) is None:
            issues.append(
                _issue(
                    "unknown_rule_id",
                    f"Unknown rule_id {rule_id!r}.",
                    source=source,
                    item=item,
                    rule_id=rule_id,
                )
            )
    for claim in evidence.registry_references:
        key = (
            claim.rule_id,
            claim.standard,
            claim.reference,
            claim.strength,
            claim.origin,
        )
        if key in seen_claims:
            issues.append(
                _issue(
                    "registry_reference_mismatch",
                    "Duplicate registry reference claim.",
                    source=source,
                    item=item,
                    rule_id=claim.rule_id,
                )
            )
            continue
        seen_claims.add(key)
        if claim.rule_id not in evidence.rule_ids:
            issues.append(
                _issue(
                    "registry_reference_mismatch",
                    f"Registry claim rule {claim.rule_id!r} is not listed in rule_ids.",
                    source=source,
                    item=item,
                    rule_id=claim.rule_id,
                )
            )
        meta = registry.get_meta(claim.rule_id)
        if meta is None:
            if claim.rule_id not in evidence.rule_ids:
                issues.append(
                    _issue(
                        "unknown_rule_id",
                        f"Unknown rule_id {claim.rule_id!r}.",
                        source=source,
                        item=item,
                        rule_id=claim.rule_id,
                    )
                )
            continue
        refs = (*meta.standards, *meta.standards_secondary)
        exact = [
            ref
            for ref in refs
            if ref.standard == claim.standard
            and ref.reference == claim.reference
            and ref.coverage == claim.strength
            and ref.origin == claim.origin
        ]
        if not exact:
            pair_exists = any(
                ref.standard == claim.standard and ref.reference == claim.reference
                for ref in refs
            )
            issues.append(
                _issue(
                    (
                        "registry_reference_mismatch"
                        if pair_exists
                        else "registry_reference_missing"
                    ),
                    f"Registry claim does not match live metadata for "
                    f"{claim.rule_id!r}.",
                    source=source,
                    item=item,
                    rule_id=claim.rule_id,
                )
            )
    claims_by_rule = {
        claim.rule_id
        for claim in evidence.registry_references
        if _claim_matches_item_reference(item, claim.standard, claim.reference)
    }
    for rule_id in evidence.rule_ids:
        if rule_id not in claims_by_rule:
            issues.append(
                _issue(
                    "registry_reference_missing",
                    f"Rule {rule_id!r} has no registry claim matching the counted item.",
                    source=source,
                    item=item,
                    rule_id=rule_id,
                )
            )

    if item.status == "full":
        declared_direct = any(
            claim.strength == "direct" and claim.origin == "declared"
            and _registry_claim_is_primary(registry, claim)
            for claim in evidence.registry_references
            if _claim_matches_item_reference(
                item,
                claim.standard,
                claim.reference,
            )
        )
        has_derived_claim = any(
            claim.origin == "derived"
            for claim in evidence.registry_references
            if _claim_matches_item_reference(
                item,
                claim.standard,
                claim.reference,
            )
        )
        if has_derived_claim and not declared_direct:
            issues.append(
                _issue(
                    "derived_reference_used_for_full",
                    "Derived references cannot independently support full coverage.",
                    source=source,
                    item=item,
                )
            )
        has_non_registry_evidence = any(
            kind != "registry-export" for kind in evidence.evidence_kinds
        )
        if not declared_direct or not has_non_registry_evidence:
            issues.append(
                _issue(
                    "insufficient_full_evidence",
                    "Full coverage requires declared direct registry evidence "
                    "and at least one non-registry evidence kind.",
                    source=source,
                    item=item,
                )
            )
    elif item.status == "partial":
        matching_evidence = bool(claims_by_rule)
        if (
            not evidence.limitations
            or not (
                matching_evidence
                or "policy-review" in evidence.evidence_kinds
            )
        ):
            issues.append(
                _issue(
                    "insufficient_partial_evidence",
                    "Partial coverage requires real evidence and an explicit limitation.",
                    source=source,
                    item=item,
                )
            )
    elif item.status == "policy-review":
        tagged = any(
            (meta := registry.get_meta(rule_id)) is not None
            and "policy-review" in meta.tags
            for rule_id in evidence.rule_ids
        )
        if not tagged and "policy-review" not in evidence.evidence_kinds:
            issues.append(
                _issue(
                    "invalid_policy_review_evidence",
                    "Policy-review status requires tagged or explicit review evidence.",
                    source=source,
                    item=item,
                )
            )
    elif item.status == "uncovered":
        if (
            evidence.rule_ids
            or evidence.registry_references
            or evidence.evidence_kinds
        ):
            issues.append(
                _issue(
                    "uncovered_item_has_positive_evidence",
                    "Uncovered item cannot contain positive supporting evidence.",
                    source=source,
                    item=item,
                )
            )
    elif item.status == "excluded" and (
        evidence.rule_ids
        or evidence.registry_references
        or evidence.evidence_kinds
    ):
        issues.append(
            _issue(
                "uncovered_item_has_positive_evidence",
                "Excluded item cannot contain positive supporting evidence.",
                source=source,
                item=item,
            )
        )
    return issues


def _registry_claim_is_primary(
    registry: RuleRegistry,
    claim: RegistryReferenceClaim,
) -> bool:
    meta = registry.get_meta(claim.rule_id)
    if meta is None:
        return False
    return any(
        ref.standard == claim.standard
        and ref.reference == claim.reference
        and ref.coverage == claim.strength
        and ref.origin == claim.origin
        and ref.tier == "primary"
        for ref in meta.standards
    )


def _claim_matches_item_reference(
    item: CoverageItem,
    standard: str,
    reference: str,
) -> bool:
    return any(
        control.standard == standard
        and (
            control.reference == reference
            or reference in control.grouped_references
        )
        for control in item.references
    )


def _summarize_source(source: CoverageSource) -> SourceCoverageSummary:
    counts = Counter(item.status for item in source.items)
    applicable = sum(counts[status] for status in _APPLICABLE_STATUSES)
    percent = (
        Decimal("0.0")
        if applicable == 0
        else (
            Decimal(counts["full"])
            / Decimal(applicable)
            * Decimal(100)
        ).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    )
    return SourceCoverageSummary(
        source_id=source.source_id,
        title=source.title,
        applicable=applicable,
        full=counts["full"],
        partial=counts["partial"],
        policy_review=counts["policy-review"],
        uncovered=counts["uncovered"],
        excluded=counts["excluded"],
        full_percent=percent,
    )


def _reject_unsafe_yaml(text: str, display_path: str) -> None:
    try:
        for token in yaml.scan(text):
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise _load_error(
                    "ledger_yaml_invalid",
                    "Coverage ledger cannot contain YAML aliases, anchors, or tags.",
                    path=display_path,
                )
            if isinstance(token, ScalarToken) and token.value == "<<":
                raise _load_error(
                    "ledger_yaml_invalid",
                    "Coverage ledger cannot contain YAML merge keys.",
                    path=display_path,
                )
    except CoverageLedgerLoadError:
        raise
    except yaml.YAMLError as exc:
        raise _load_error(
            "ledger_yaml_invalid",
            f"Coverage ledger YAML is invalid: {exc}",
            path=display_path,
        ) from exc


def _reject_non_string_keys(value: Any, display_path: str) -> None:
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise _load_error(
                "ledger_yaml_invalid",
                "Coverage ledger mappings must use scalar string keys.",
                path=display_path,
            )
        for child in value.values():
            _reject_non_string_keys(child, display_path)
    elif isinstance(value, list):
        for child in value:
            _reject_non_string_keys(child, display_path)


def _markdown_cell(value: object) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r\n", "<br>")
        .replace("\n", "<br>")
        .strip()
    )


def _read_markdown_summary(
    path: Path,
) -> dict[str, tuple[int, int, int, int, int, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    summaries: dict[str, tuple[int, int, int, int, int, str]] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) != 7:
            continue
        try:
            counts = tuple(int(cell) for cell in cells[1:6])
        except ValueError:
            continue
        summaries[cells[0]] = (*counts, cells[6])
    return summaries


def _source_id_for_title(ledger: CoverageLedger, title: str) -> str | None:
    return next(
        (source.source_id for source in ledger.sources if source.title == title),
        None,
    )


def _load_error(
    code: str,
    message: str,
    *,
    path: str | None = None,
) -> CoverageLedgerLoadError:
    return CoverageLedgerLoadError(
        CoverageLedgerIssue(code=code, message=message, path=path)
    )


def _issue(
    code: str,
    message: str,
    *,
    source: CoverageSource,
    item: CoverageItem | None = None,
    rule_id: str | None = None,
) -> CoverageLedgerIssue:
    return CoverageLedgerIssue(
        code=code,
        message=message,
        source_id=source.source_id,
        item_id=item.item_id if item is not None else None,
        rule_id=rule_id,
    )


def _issue_sort_key(
    issue: CoverageLedgerIssue,
) -> tuple[str, str, str, str, str, str]:
    return (
        issue.source_id or "",
        issue.item_id or "",
        issue.rule_id or "",
        issue.code,
        issue.path or "",
        issue.message,
    )


__all__ = [
    "CoverageLedgerLoadError",
    "DEFAULT_LEDGER_MAX_BYTES",
    "check_coverage_documentation",
    "load_coverage_ledger",
    "render_coverage_markdown",
    "render_coverage_json",
    "summarize_coverage",
    "validate_coverage_ledger",
    "write_coverage_output",
]
