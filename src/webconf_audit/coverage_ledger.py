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
    CoverageReconciliation,
    CoverageItem,
    CoverageLedger,
    CoverageLedgerIssue,
    CoverageStatusChange,
    CoverageSource,
    GeneratedCoverageArtifact,
    ReconciledSourceCoverage,
    RegistryReferenceClaim,
    SourceCoverageDelta,
    SourceCoverageSummary,
    SourceRecount,
)
from webconf_audit.rule_registry import RuleRegistry
from webconf_audit.standard_catalog import (
    find_standard_source,
    is_valid_ledger_reference,
)

DEFAULT_LEDGER_MAX_BYTES = 2 * 1024 * 1024
_PACKAGED_LEDGER = "control_source_coverage.yml"
_APPLICABLE_STATUSES = ("full", "partial", "policy-review", "uncovered")
_RECONCILIATION_SNAPSHOT_BEGIN = "<!-- BEGIN GENERATED: coverage-snapshot -->"
_RECONCILIATION_SNAPSHOT_END = "<!-- END GENERATED: coverage-snapshot -->"
_RECONCILIATION_ROADMAP_BEGIN = (
    "<!-- BEGIN GENERATED: final-coverage-reconciliation -->"
)
_RECONCILIATION_ROADMAP_END = "<!-- END GENERATED: final-coverage-reconciliation -->"
_FINAL_CHANGE_REF = "followup-14-final-cross-standard-reconciliation"
_PROGRAM_BASELINE_RECOUNTS: tuple[SourceRecount, ...] = (
    SourceRecount(
        source_id="cis-nginx-3.0.0",
        title="CIS NGINX Benchmark v3.0.0",
        version="3.0.0",
        applicable=15,
        full=7,
        partial=7,
        policy_review=1,
        uncovered=0,
        excluded=0,
        full_percent=Decimal("46.7"),
    ),
    SourceRecount(
        source_id="cis-apache-http-server-2.4-2.3.0",
        title="CIS Apache HTTP Server 2.4 Benchmark v2.3.0",
        version="2.3.0",
        applicable=19,
        full=17,
        partial=2,
        policy_review=0,
        uncovered=0,
        excluded=0,
        full_percent=Decimal("89.5"),
    ),
    SourceRecount(
        source_id="cis-microsoft-iis-10-1.2.1",
        title="CIS Microsoft IIS 10 Benchmark v1.2.1",
        version="1.2.1",
        applicable=10,
        full=8,
        partial=1,
        policy_review=0,
        uncovered=1,
        excluded=0,
        full_percent=Decimal("80.0"),
    ),
    SourceRecount(
        source_id="owasp-top10-2025",
        title="OWASP Top 10:2025",
        version="2025",
        applicable=8,
        full=2,
        partial=6,
        policy_review=0,
        uncovered=0,
        excluded=2,
        full_percent=Decimal("25.0"),
    ),
    SourceRecount(
        source_id="owasp-asvs-5.0.0",
        title="OWASP ASVS v5.0.0",
        version="5.0.0",
        applicable=22,
        full=15,
        partial=7,
        policy_review=0,
        uncovered=0,
        excluded=0,
        full_percent=Decimal("68.2"),
    ),
    SourceRecount(
        source_id="nist-sp-800-52r2",
        title="NIST SP 800-52 Rev. 2",
        version="Rev. 2",
        applicable=10,
        full=10,
        partial=0,
        policy_review=0,
        uncovered=0,
        excluded=0,
        full_percent=Decimal("100.0"),
    ),
    SourceRecount(
        source_id="pci-dss-4.0.1",
        title="PCI DSS v4.0.1",
        version="4.0.1",
        applicable=11,
        full=11,
        partial=0,
        policy_review=0,
        uncovered=0,
        excluded=2,
        full_percent=Decimal("100.0"),
    ),
    SourceRecount(
        source_id="iso-iec-27002-2022",
        title="ISO/IEC 27002:2022",
        version="2022",
        applicable=10,
        full=8,
        partial=2,
        policy_review=0,
        uncovered=0,
        excluded=0,
        full_percent=Decimal("80.0"),
    ),
)
_FINAL_STATUS_BASELINE_BY_ITEM: dict[str, str] = {
    "nginx-4.1.2-trusted-certificate-chain": "partial",
    "apache-2.1-module-minimization": "partial",
    "iis-7.1-schannel-tls": "partial",
    "nist-3.3.1-recommended-cipher-posture": "full",
    "nist-3.3.2-server-cipher-preference": "full",
    "nist-4.2-ocsp-must-staple": "full",
    "nist-4.3-revocation-evidence": "full",
}
_PROHIBITED_COMPLIANCE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("cis compliant", "Use scanner-evidence coverage wording, not compliance claims."),
    ("owasp compliant", "Use scanner-evidence coverage wording, not compliance claims."),
    ("asvs certified", "Use scanner-evidence coverage wording, not certification claims."),
    ("nist compliant", "Use scanner-evidence coverage wording, not compliance claims."),
    ("pci dss compliant", "Use scanner-evidence coverage wording, not compliance claims."),
    ("iso 27002 compliant", "Use scanner-evidence coverage wording, not compliance claims."),
    (
        "fully implements the organizational control",
        "Keep ISO and similar mappings bounded to technical-control alignment.",
    ),
    (
        "all tls endpoints are secure",
        "Bound TLS statements to the declared inventory and observed scope.",
    ),
)
_ALLOWED_NEGATION_SNIPPETS = (
    "does not certify compliance",
    "not a claim of certification",
    "does not emit a compliance percentage",
    "does not claim",
)


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
    enforce_program_baseline = bool(ledger.snapshot.accepted_revisions)
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
        issues.extend(
            _validate_source(
                source,
                registry,
                enforce_program_baseline=enforce_program_baseline,
            )
        )
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
        "refresh with `webconf-audit coverage reconcile --write`. -->",
        "# Control Source Coverage Tracker",
        "",
        "This generated view summarizes scanner-evidence coverage within the "
        "declared project scope. It does not certify compliance with any source.",
        "",
        "Target assessment is reported separately through "
        "`webconf-audit assess`; coverage status is not a per-target result.",
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


def reconcile_coverage_documents(
    ledger: CoverageLedger,
    registry: RuleRegistry,
    *,
    repo_root: Path | None = None,
) -> CoverageReconciliation:
    """Render the synchronized final coverage snapshot artifacts."""
    del registry  # Reserved for future typed reconciliation checks.
    repo_root = repo_root or Path(__file__).resolve().parents[2]
    baseline_by_source = {
        recount.source_id: recount for recount in _PROGRAM_BASELINE_RECOUNTS
    }
    reconciled_sources: list[ReconciledSourceCoverage] = []
    for source in ledger.sources:
        baseline = baseline_by_source.get(source.source_id)
        if baseline is None:
            baseline = _source_recount(source)
        current = _source_recount(source)
        changed_items = tuple(
            CoverageStatusChange(
                source_id=source.source_id,
                item_id=item.item_id,
                title=item.title,
                from_status=_FINAL_STATUS_BASELINE_BY_ITEM[item.item_id],  # type: ignore[arg-type]
                to_status=item.status,
                change_ref=item.provenance.change_ref,
            )
            for item in source.items
            if item.item_id in _FINAL_STATUS_BASELINE_BY_ITEM
        )
        reconciled_sources.append(
            ReconciledSourceCoverage(
                source_id=source.source_id,
                title=source.title,
                baseline=baseline,
                current=current,
                delta=_source_delta(baseline, current),
                changed_items=changed_items,
                denominator_notes=source.denominator_notes,
            )
        )
    reconciliation = CoverageReconciliation(
        sources=tuple(reconciled_sources),
        artifacts=(
            GeneratedCoverageArtifact(
                label="coverage-tracker",
                path=str(repo_root / "docs" / "control-source-coverage-tracker.md"),
                content=render_coverage_markdown(ledger),
            ),
            GeneratedCoverageArtifact(
                label="benchmarks-snapshot",
                path=str(repo_root / "docs" / "benchmarks-covering.md"),
                content=_render_benchmark_document(
                    repo_root / "docs" / "benchmarks-covering.md",
                    tuple(reconciled_sources),
                ),
            ),
            GeneratedCoverageArtifact(
                label="standards-roadmap-final-reconciliation",
                path=str(repo_root / "docs" / "standards-roadmap.md"),
                content=_render_standards_roadmap_document(
                    repo_root / "docs" / "standards-roadmap.md",
                    ledger,
                    tuple(reconciled_sources),
                ),
            ),
        ),
    )
    return reconciliation


def check_coverage_reconciliation(
    ledger: CoverageLedger,
    registry: RuleRegistry,
    *,
    repo_root: Path | None = None,
    compare_tracked: bool = True,
) -> tuple[CoverageLedgerIssue, ...]:
    """Validate the final reconciliation state across ledger and synced docs."""
    repo_root = repo_root or Path(__file__).resolve().parents[2]
    issues = list(validate_coverage_ledger(ledger, registry))
    reconciliation = reconcile_coverage_documents(
        ledger,
        registry,
        repo_root=repo_root,
    )
    issues.extend(_validate_acceptance_freeze(ledger))
    issues.extend(_validate_iis_ftp_invariant(ledger))
    if compare_tracked:
        issues.extend(_compare_reconciled_artifacts(reconciliation))
        issues.extend(
            _scan_prohibited_compliance_language(
                (
                    repo_root / "README.md",
                    repo_root / "docs" / "architecture.md",
                    repo_root / "docs" / "benchmarks-covering.md",
                    repo_root / "docs" / "control-source-coverage-tracker.md",
                    repo_root / "docs" / "standards-roadmap.md",
                )
            )
        )
    else:
        issues.extend(
            _scan_prohibited_compliance_texts(
                tuple(
                    (artifact.path, artifact.content)
                    for artifact in reconciliation.artifacts
                )
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


def write_coverage_reconciliation(
    reconciliation: CoverageReconciliation,
) -> tuple[CoverageLedgerIssue, ...]:
    """Replace all rendered reconciliation artifacts as one atomic unit."""
    outputs = {
        Path(artifact.path): artifact.content for artifact in reconciliation.artifacts
    }
    issues = _preflight_reconciliation_outputs(outputs)
    if issues:
        return issues

    try:
        with tempfile.TemporaryDirectory(
            dir=str(_common_output_root(outputs))
        ) as temp_root_name:
            temp_root = Path(temp_root_name)
            staged: dict[Path, Path] = {}
            backups: dict[Path, Path] = {}
            replaced: list[Path] = []
            for output_path, content in outputs.items():
                output_path.parent.mkdir(parents=True, exist_ok=True)
                staged_path = temp_root / f"{len(staged):02d}-{output_path.name}"
                with staged_path.open("w", encoding="utf-8", newline="\n") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                staged[output_path] = staged_path

            try:
                for output_path in sorted(outputs):
                    if output_path.exists():
                        backup_path = temp_root / f"backup-{len(backups):02d}-{output_path.name}"
                        os.replace(output_path, backup_path)
                        backups[output_path] = backup_path
                    os.replace(staged[output_path], output_path)
                    replaced.append(output_path)
            except OSError as exc:
                for output_path in reversed(replaced):
                    try:
                        output_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    backup = backups.get(output_path)
                    if backup is not None and backup.exists():
                        os.replace(backup, output_path)
                for output_path, backup in backups.items():
                    if output_path not in replaced and backup.exists():
                        os.replace(backup, output_path)
                return (
                    CoverageLedgerIssue(
                        code="reconciliation_write_failed",
                        message=(
                            "Could not atomically publish reconciled coverage "
                            f"artifacts: {exc}"
                        ),
                    ),
                )
    except OSError as exc:
        return (
            CoverageLedgerIssue(
                code="reconciliation_write_failed",
                message=(
                    "Could not stage reconciled coverage artifacts for atomic "
                    f"publish: {exc}"
                ),
            ),
        )
    return ()


def _source_recount(source: CoverageSource) -> SourceRecount:
    summary = _summarize_source(source)
    return SourceRecount(
        source_id=source.source_id,
        title=source.title,
        version=source.version,
        applicable=summary.applicable,
        full=summary.full,
        partial=summary.partial,
        policy_review=summary.policy_review,
        uncovered=summary.uncovered,
        excluded=summary.excluded,
        full_percent=summary.full_percent,
    )


def _source_delta(
    baseline: SourceRecount,
    current: SourceRecount,
) -> SourceCoverageDelta:
    return SourceCoverageDelta(
        applicable=current.applicable - baseline.applicable,
        full=current.full - baseline.full,
        partial=current.partial - baseline.partial,
        policy_review=current.policy_review - baseline.policy_review,
        uncovered=current.uncovered - baseline.uncovered,
        excluded=current.excluded - baseline.excluded,
    )


def _render_benchmark_document(
    path: Path,
    sources: tuple[ReconciledSourceCoverage, ...],
) -> str:
    text = path.read_text(encoding="utf-8")
    generated = _render_benchmark_snapshot_section(sources)
    return _replace_generated_section(
        text,
        _RECONCILIATION_SNAPSHOT_BEGIN,
        _RECONCILIATION_SNAPSHOT_END,
        generated,
    )


def _render_standards_roadmap_document(
    path: Path,
    ledger: CoverageLedger,
    sources: tuple[ReconciledSourceCoverage, ...],
) -> str:
    text = path.read_text(encoding="utf-8")
    generated = _render_standards_reconciliation_section(ledger, sources)
    return _replace_generated_section(
        text,
        _RECONCILIATION_ROADMAP_BEGIN,
        _RECONCILIATION_ROADMAP_END,
        generated,
    )


def _render_benchmark_snapshot_section(
    sources: tuple[ReconciledSourceCoverage, ...],
) -> str:
    changed_items = [
        change
        for source in sources
        for change in source.changed_items
    ]
    denominator_notes = [
        (source.title, note)
        for source in sources
        for note in source.denominator_notes
    ]
    lines = [
        "### 4.1 Current coverage snapshot",
        "",
        "The final post-program snapshot is computed from the packaged coverage "
        "ledger. It reports scanner-evidence coverage within the documented "
        "scope; it does not certify CIS, OWASP, ASVS, NIST, PCI DSS, or ISO "
        "compliance.",
        "",
        "Historical PR #9 before snapshot:",
        "",
        "| Control source | Applicable items | Fully covered | Partially covered | Policy review | Uncovered | Full coverage |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for source in sources:
        baseline = source.baseline
        lines.append(
            f"| {_markdown_cell(source.title)} | {baseline.applicable} | {baseline.full} | "
            f"{baseline.partial} | {baseline.policy_review} | {baseline.uncovered} | "
            f"{baseline.full_percent:.1f}% |"
        )
    lines.extend(
        [
            "",
            "Final reconciled snapshot (accepted follow-ups 01-13 frozen in the "
            "standards roadmap section below):",
            "",
            "| Control source | Applicable items | Fully covered | Partially covered | Policy review | Uncovered | Full coverage |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for source in sources:
        current = source.current
        lines.append(
            f"| {_markdown_cell(source.title)} | {current.applicable} | {current.full} | "
            f"{current.partial} | {current.policy_review} | {current.uncovered} | "
            f"{current.full_percent:.1f}% |"
        )
    lines.extend(
        [
            "",
            "Per-source numerator and denominator deltas vs PR #9:",
            "",
            "| Control source | Applicable delta | Full delta | Partial delta | Policy review delta | Uncovered delta |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for source in sources:
        delta = source.delta
        lines.append(
            f"| {_markdown_cell(source.title)} | {delta.applicable:+d} | {delta.full:+d} | "
            f"{delta.partial:+d} | {delta.policy_review:+d} | {delta.uncovered:+d} |"
        )
    if changed_items:
        lines.extend(
            [
                "",
                "Status changes finalized by this recount:",
                "",
                "| Counted item | Source | Status change | Accepted implementation |",
                "| --- | --- | --- | --- |",
            ]
        )
        for change in changed_items:
            lines.append(
                f"| `{change.item_id}` { _markdown_cell(change.title)} | "
                f"{_markdown_cell(next(source.title for source in sources if source.source_id == change.source_id))} | "
                f"`{change.from_status}` -> `{change.to_status}` | `{change.change_ref}` |"
            )
    if denominator_notes:
        lines.extend(
            [
                "",
                "Explicit denominator changes:",
                "",
                "| Source | Applicable delta | Reason |",
                "| --- | ---: | --- |",
            ]
        )
        for title, note in denominator_notes:
            lines.append(
                f"| {_markdown_cell(title)} | {note.delta_applicable:+d} | "
                f"{_markdown_cell(note.reason)} (`{note.change_ref}`) |"
            )
    lines.extend(
        [
            "",
            "Unchanged conservative boundaries remain explicit in the ledger:",
            "",
            "- IIS FTP Section 6.1 / 6.2 remains one applicable `uncovered` item in the IIS denominator.",
            "- OWASP Top 10:2025 remains bounded category alignment rather than application-wide coverage proof.",
            "- ASVS TLS cipher and revocation groups stay `partial` where only bounded runtime evidence is available.",
            "- PCI DSS organizational, governance, and password-reset process controls remain outside scanner-evidence `full` coverage.",
            "",
            "Each source reconciles as `Applicable = Full + Partial + Policy review + "
            "Uncovered`. Excluded items do not enter the applicable denominator. "
            "The counted-item ledger and evidence rationale are recorded in "
            "`docs/control-source-coverage-tracker.md`.",
        ]
    )
    return "\n".join(lines)


def _render_standards_reconciliation_section(
    ledger: CoverageLedger,
    sources: tuple[ReconciledSourceCoverage, ...],
) -> str:
    lines = [
        "## Final Counted Coverage Reconciliation (2026-06-16)",
        "",
        "This terminal program recount freezes the accepted follow-up merge SHAs, "
        "recomputes each counted source from the packaged ledger, and keeps "
        "generated coverage prose synchronized with the rule registry and the "
        "machine-readable tracker.",
        "",
        "Accepted follow-up merge SHAs:",
        "",
        "| Follow-up | Merge SHA | Summary |",
        "| --- | --- | --- |",
    ]
    for revision in ledger.snapshot.accepted_revisions:
        lines.append(
            f"| `{revision.step_id}` | `{revision.merge_sha}` | "
            f"{_markdown_cell(revision.summary)} |"
        )
    lines.extend(
        [
            "",
            "Final source snapshot:",
            "",
            "| Control source | Applicable | Full | Partial | `policy-review` | Uncovered | Full coverage |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for source in sources:
        current = source.current
        lines.append(
            f"| {_markdown_cell(source.title)} | {current.applicable} | {current.full} | "
            f"{current.partial} | {current.policy_review} | {current.uncovered} | "
            f"{current.full_percent:.1f}% |"
        )
    lines.extend(
        [
            "",
            "Reconciliation guardrails:",
            "",
            "- Apache's denominator is explicitly +1 versus PR #9 because follow-up 11 split the historical grouped CIS 4.1 / 4.2 row into two counted items.",
            "- IIS FTP remains visible, applicable, `uncovered`, and outside implementation scope.",
            "- NIST TLS rows that still rely on bounded cipher-preference or revocation observations remain `partial` rather than inheriting an old 100% snapshot.",
            "- Documentation uses scanner-scope and technical-control-alignment wording rather than compliance or certification language.",
        ]
    )
    return "\n".join(lines)


def _replace_generated_section(
    text: str,
    begin_marker: str,
    end_marker: str,
    replacement: str,
) -> str:
    begin = text.find(begin_marker)
    end = text.find(end_marker)
    if begin == -1 or end == -1 or end < begin:
        raise ValueError(
            f"Missing generated section markers {begin_marker!r} / {end_marker!r}."
        )
    end += len(end_marker)
    block = f"{begin_marker}\n{replacement.rstrip()}\n{end_marker}"
    return text[:begin] + block + text[end:]


def _validate_acceptance_freeze(
    ledger: CoverageLedger,
) -> tuple[CoverageLedgerIssue, ...]:
    revisions = ledger.snapshot.accepted_revisions
    expected_steps = {f"followup-{index:02d}" for index in range(1, 14)}
    actual_steps = {revision.step_id for revision in revisions}
    if actual_steps != expected_steps:
        return (
            CoverageLedgerIssue(
                code="accepted_revisions_missing",
                message=(
                    "Coverage snapshot must freeze accepted follow-up merge SHAs "
                    f"01-13; got {sorted(actual_steps)!r}."
                ),
            ),
        )
    return ()


def _validate_iis_ftp_invariant(
    ledger: CoverageLedger,
) -> tuple[CoverageLedgerIssue, ...]:
    source = next(
        (
            candidate
            for candidate in ledger.sources
            if candidate.source_id == "cis-microsoft-iis-10-1.2.1"
        ),
        None,
    )
    if source is None:
        return (
            CoverageLedgerIssue(
                code="iis_ftp_invariant_failed",
                message="IIS source is missing from the coverage ledger.",
                source_id="cis-microsoft-iis-10-1.2.1",
            ),
        )
    item = next(
        (candidate for candidate in source.items if candidate.item_id == "iis-6.1-ftp-encryption-logon-restrictions"),
        None,
    )
    if item is None:
        return (
            CoverageLedgerIssue(
                code="iis_ftp_invariant_failed",
                message="IIS FTP grouped item is missing from the coverage ledger.",
                source_id=source.source_id,
            ),
        )
    issues: list[CoverageLedgerIssue] = []
    if item.status != "uncovered" or item.applicability != "applicable":
        issues.append(
            CoverageLedgerIssue(
                code="iis_ftp_invariant_failed",
                message="IIS FTP must remain applicable and uncovered.",
                source_id=source.source_id,
                item_id=item.item_id,
            )
        )
    if item.evidence.rule_ids or item.evidence.assessment_rules or item.evidence.assessment_controls:
        issues.append(
            CoverageLedgerIssue(
                code="iis_ftp_invariant_failed",
                message="IIS FTP must not gain rule or control bindings in the reconciliation.",
                source_id=source.source_id,
                item_id=item.item_id,
            )
        )
    return tuple(issues)


def _compare_reconciled_artifacts(
    reconciliation: CoverageReconciliation,
) -> tuple[CoverageLedgerIssue, ...]:
    issues: list[CoverageLedgerIssue] = []
    for artifact in reconciliation.artifacts:
        path = Path(artifact.path)
        try:
            actual = path.read_text(encoding="utf-8")
        except OSError:
            actual = ""
        if actual != artifact.content:
            issues.append(
                CoverageLedgerIssue(
                    code="reconciliation_render_drift",
                    message=f"{path} does not match the reconciled coverage render.",
                    path=str(path),
                )
            )
    return tuple(issues)


def _scan_prohibited_compliance_language(
    paths: tuple[Path, ...],
) -> tuple[CoverageLedgerIssue, ...]:
    entries: list[tuple[str, str]] = []
    for path in paths:
        try:
            entries.append((str(path), path.read_text(encoding="utf-8")))
        except OSError:
            continue
    return _scan_prohibited_compliance_texts(tuple(entries))


def _scan_prohibited_compliance_texts(
    entries: tuple[tuple[str, str], ...],
) -> tuple[CoverageLedgerIssue, ...]:
    issues: list[CoverageLedgerIssue] = []
    for label, text in entries:
        lowered = text.lower()
        for phrase, hint in _PROHIBITED_COMPLIANCE_PATTERNS:
            if phrase not in lowered:
                continue
            line = next(
                (
                    candidate
                    for candidate in text.splitlines()
                    if phrase in candidate.lower()
                ),
                phrase,
            )
            if any(allow in line.lower() for allow in _ALLOWED_NEGATION_SNIPPETS):
                continue
            issues.append(
                CoverageLedgerIssue(
                    code="prohibited_compliance_language",
                    message=(
                        f"{label} contains prohibited wording {phrase!r}. {hint}"
                    ),
                    path=label,
                )
            )
    return tuple(issues)


def _preflight_reconciliation_outputs(
    outputs: dict[Path, str],
) -> tuple[CoverageLedgerIssue, ...]:
    issues: list[CoverageLedgerIssue] = []
    for path in outputs:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            issues.append(
                CoverageLedgerIssue(
                    code="reconciliation_write_failed",
                    message=f"Could not prepare parent directory for {path}: {exc}",
                    path=str(path),
                )
            )
            continue
        if path.is_symlink():
            issues.append(
                CoverageLedgerIssue(
                    code="reconciliation_write_failed",
                    message=f"Refusing to replace symlink output path: {path}",
                    path=str(path),
                )
            )
            continue
        if path.exists() and not path.is_file():
            issues.append(
                CoverageLedgerIssue(
                    code="reconciliation_write_failed",
                    message=f"Reconciled output path is not a regular file: {path}",
                    path=str(path),
                )
            )
    return tuple(issues)


def _common_output_root(outputs: dict[Path, str]) -> Path:
    roots = [path.parent.resolve() for path in outputs]
    common = Path(os.path.commonpath([str(root) for root in roots]))
    return common


def _validate_source(
    source: CoverageSource,
    registry: RuleRegistry,
    *,
    enforce_program_baseline: bool,
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
    baseline = next(
        (
            recount
            for recount in _PROGRAM_BASELINE_RECOUNTS
            if recount.source_id == source.source_id
        ),
        None,
    )
    if baseline is not None and enforce_program_baseline:
        denominator_delta = actual.applicable - baseline.applicable
        if denominator_delta != 0:
            declared_delta = sum(note.delta_applicable for note in source.denominator_notes)
            if declared_delta != denominator_delta or not source.denominator_notes:
                issues.append(
                    _issue(
                        "missing_denominator_change_reason",
                        (
                            "Applicable-denominator changes must carry a machine-readable "
                            f"reason; expected delta {denominator_delta:+d}, got "
                            f"{declared_delta:+d}."
                        ),
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
    seen_assessment_rules: set[str] = set()
    claims_for_item = [
        claim
        for claim in evidence.registry_references
        if _claim_matches_item_reference(item, claim.standard, claim.reference)
    ]
    for assessment_rule in evidence.assessment_rules:
        if assessment_rule.rule_id in seen_assessment_rules:
            issues.append(
                _issue(
                    "registry_reference_mismatch",
                    (
                        "Assessment evidence cannot repeat the same rule_id within "
                        "one control item."
                    ),
                    source=source,
                    item=item,
                    rule_id=assessment_rule.rule_id,
                )
            )
            continue
        seen_assessment_rules.add(assessment_rule.rule_id)
        if assessment_rule.rule_id not in evidence.rule_ids:
            issues.append(
                _issue(
                    "registry_reference_mismatch",
                    (
                        f"Assessment evidence rule {assessment_rule.rule_id!r} is "
                        "not listed in rule_ids."
                    ),
                    source=source,
                    item=item,
                    rule_id=assessment_rule.rule_id,
                )
            )
        matching_claim = next(
            (
                claim
                for claim in claims_for_item
                if claim.rule_id == assessment_rule.rule_id
                and claim.strength == assessment_rule.strength
                and claim.origin == assessment_rule.origin
            ),
            None,
        )
        if matching_claim is None:
            issues.append(
                _issue(
                    "registry_reference_mismatch",
                    (
                        "Assessment evidence must match a registry reference claim "
                        "for the counted item."
                    ),
                    source=source,
                    item=item,
                    rule_id=assessment_rule.rule_id,
                )
            )
            continue
        if assessment_rule.origin == "derived" and assessment_rule.absence_semantics != "none":
            issues.append(
                _issue(
                    "registry_reference_mismatch",
                    "Derived assessment evidence must use absence_semantics 'none'.",
                    source=source,
                    item=item,
                    rule_id=assessment_rule.rule_id,
                )
            )
        if assessment_rule.strength == "related" and assessment_rule.absence_semantics != "none":
            issues.append(
                _issue(
                    "registry_reference_mismatch",
                    "Related assessment evidence must use absence_semantics 'none'.",
                    source=source,
                    item=item,
                    rule_id=assessment_rule.rule_id,
                )
            )
        meta = registry.get_meta(assessment_rule.rule_id)
        if (
            meta is not None
            and "policy-review" in meta.tags
            and assessment_rule.absence_semantics != "none"
        ):
            issues.append(
                _issue(
                    "registry_reference_mismatch",
                    (
                        "Rules tagged 'policy-review' cannot define automated "
                        "pass semantics."
                    ),
                    source=source,
                    item=item,
                    rule_id=assessment_rule.rule_id,
                )
            )
        if (
            assessment_rule.absence_semantics == "control-pass"
            and not (
                assessment_rule.strength == "direct"
                and assessment_rule.origin == "declared"
            )
        ):
            issues.append(
                _issue(
                    "registry_reference_mismatch",
                    (
                        "control-pass evidence requires a declared direct mapping "
                        "for the counted item."
                    ),
                    source=source,
                    item=item,
                    rule_id=assessment_rule.rule_id,
                )
            )
    seen_assessment_controls: set[str] = set()
    for assessment_control in evidence.assessment_controls:
        if assessment_control.control_id in seen_assessment_controls:
            issues.append(
                _issue(
                    "assessment_control_mapping_invalid",
                    (
                        "Assessment control evidence cannot repeat the same "
                        "control_id within one control item."
                    ),
                    source=source,
                    item=item,
                )
            )
            continue
        seen_assessment_controls.add(assessment_control.control_id)
        if (
            assessment_control.origin == "derived"
            and assessment_control.absence_semantics != "none"
        ):
            issues.append(
                _issue(
                    "assessment_control_mapping_invalid",
                    (
                        "Derived assessment control evidence must use "
                        "absence_semantics 'none'."
                    ),
                    source=source,
                    item=item,
                )
            )
        if (
            assessment_control.strength == "related"
            and assessment_control.absence_semantics != "none"
        ):
            issues.append(
                _issue(
                    "assessment_control_mapping_invalid",
                    (
                        "Related assessment control evidence must use "
                        "absence_semantics 'none'."
                    ),
                    source=source,
                    item=item,
                )
            )
        if (
            assessment_control.absence_semantics == "control-pass"
            and not (
                assessment_control.strength == "direct"
                and assessment_control.origin == "declared"
            )
        ):
            issues.append(
                _issue(
                    "assessment_control_mapping_invalid",
                    (
                        "control-pass assessment control evidence requires a "
                        "declared direct mapping for the counted item."
                    ),
                    source=source,
                    item=item,
                )
            )
    claims_by_rule = {claim.rule_id for claim in claims_for_item}
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
        mandatory_subclaims = tuple(
            subclaim for subclaim in item.subclaims if subclaim.mandatory
        )
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
        subclaim_direct_support = any(
            (
                binding.kind == "control"
                and binding.strength == "direct"
                and binding.origin == "declared"
            )
            or (
                binding.kind == "rule"
                and binding.strength == "direct"
                and binding.origin == "declared"
                and any(
                    claim.rule_id == binding.target
                    and claim.strength == "direct"
                    and claim.origin == "declared"
                    and _registry_claim_is_primary(registry, claim)
                    for claim in claims_for_item
                )
            )
            for subclaim in mandatory_subclaims
            for binding in subclaim.bindings
        )
        direct_support = declared_direct or subclaim_direct_support
        if has_derived_claim and not direct_support:
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
        if not direct_support or not has_non_registry_evidence:
            issues.append(
                _issue(
                    "insufficient_full_evidence",
                    "Full coverage requires declared direct registry evidence "
                    "or a declared direct control binding, plus at least one "
                    "non-registry evidence kind.",
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
    seen_subclaims: set[str] = set()
    for subclaim in item.subclaims:
        if subclaim.subclaim_id in seen_subclaims:
            issues.append(
                _issue(
                    "duplicate_subclaim_id",
                    f"Duplicate subclaim_id {subclaim.subclaim_id!r}.",
                    source=source,
                    item=item,
                )
            )
            continue
        seen_subclaims.add(subclaim.subclaim_id)
        if item.status == "full" and subclaim.mandatory and not subclaim.implemented:
            issues.append(
                _issue(
                    "full_item_missing_mandatory_subclaim",
                    (
                        "Full coverage requires every mandatory subclaim to be "
                        "implemented."
                    ),
                    source=source,
                    item=item,
                )
            )
        for binding in subclaim.bindings:
            if binding.kind == "rule":
                if binding.target not in evidence.rule_ids:
                    issues.append(
                        _issue(
                            "subclaim_binding_invalid",
                            f"Subclaim rule binding {binding.target!r} is not present in rule_ids.",
                            source=source,
                            item=item,
                            rule_id=binding.target,
                        )
                    )
                    continue
                if registry.get_meta(binding.target) is None:
                    issues.append(
                        _issue(
                            "subclaim_binding_invalid",
                            f"Subclaim rule binding {binding.target!r} is not a registered rule.",
                            source=source,
                            item=item,
                            rule_id=binding.target,
                        )
                    )
                    continue
                matching_claim = next(
                    (
                        claim
                        for claim in claims_for_item
                        if claim.rule_id == binding.target
                        and claim.strength == binding.strength
                        and claim.origin == binding.origin
                    ),
                    None,
                )
                if matching_claim is None:
                    issues.append(
                        _issue(
                            "subclaim_binding_invalid",
                            (
                                f"Subclaim rule binding {binding.target!r} must "
                                "match a counted-item registry reference claim."
                            ),
                            source=source,
                            item=item,
                            rule_id=binding.target,
                        )
                    )
            elif binding.kind == "control":
                matching_control = next(
                    (
                        entry
                        for entry in evidence.assessment_controls
                        if entry.control_id == binding.target
                        and entry.strength == binding.strength
                        and entry.origin == binding.origin
                    ),
                    None,
                )
                if matching_control is None:
                    issues.append(
                        _issue(
                            "subclaim_binding_invalid",
                            (
                                f"Subclaim control binding {binding.target!r} must "
                                "match an assessment_controls entry."
                            ),
                            source=source,
                            item=item,
                        )
                    )
            elif binding.target not in evidence.evidence_kinds:
                issues.append(
                    _issue(
                        "subclaim_binding_invalid",
                        (
                            f"Subclaim evidence-kind binding {binding.target!r} is "
                            "not present in evidence_kinds."
                        ),
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
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if (
        _RECONCILIATION_SNAPSHOT_BEGIN in text
        and _RECONCILIATION_SNAPSHOT_END in text
    ):
        begin = text.index(_RECONCILIATION_SNAPSHOT_BEGIN)
        end = text.index(_RECONCILIATION_SNAPSHOT_END)
        text = text[begin:end]
    lines = text.splitlines()
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
    "check_coverage_reconciliation",
    "CoverageLedgerLoadError",
    "DEFAULT_LEDGER_MAX_BYTES",
    "check_coverage_documentation",
    "load_coverage_ledger",
    "reconcile_coverage_documents",
    "render_coverage_markdown",
    "render_coverage_json",
    "summarize_coverage",
    "validate_coverage_ledger",
    "write_coverage_reconciliation",
    "write_coverage_output",
]
