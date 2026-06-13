"""Coverage-ledger CLI commands."""

from __future__ import annotations

from enum import Enum
import json
from pathlib import Path

import typer

from webconf_audit.coverage_ledger import (
    CoverageLedgerLoadError,
    check_coverage_documentation,
    load_coverage_ledger,
    render_coverage_markdown,
    summarize_coverage,
    validate_coverage_ledger,
    write_coverage_output,
)
from webconf_audit.coverage_models import (
    CoverageLedger,
    CoverageLedgerIssue,
    CoverageStatus,
)

coverage_app = typer.Typer(help="Validate and inspect control-source coverage claims.")


class CoverageDisplayFormat(str, Enum):
    text = "text"
    json = "json"


class CoverageExportFormat(str, Enum):
    markdown = "markdown"
    json = "json"


class CoverageStatusFilter(str, Enum):
    full = "full"
    partial = "partial"
    policy_review = "policy-review"
    uncovered = "uncovered"
    excluded = "excluded"


@coverage_app.command("validate")
def validate_command(
    ledger_path: Path | None = typer.Option(
        None,
        "--ledger",
        help="Validate a local ledger instead of the packaged canonical ledger.",
    ),
    output_format: CoverageDisplayFormat = typer.Option(
        CoverageDisplayFormat.text,
        "--format",
        "-f",
        help="Output format: text, json.",
    ),
) -> None:
    """Validate schema, source, registry, evidence, and summary integrity."""
    ledger, issues = _load_and_validate(ledger_path)
    if ledger is not None and ledger_path is None:
        documentation_paths = _repository_documentation_paths()
        if documentation_paths is not None:
            issues = (
                *issues,
                *check_coverage_documentation(
                    ledger,
                    documentation_paths[0],
                    documentation_paths[1],
                ),
            )
    if output_format == CoverageDisplayFormat.json:
        typer.echo(_render_cli_json(ledger, issues, include_items=False))
    elif issues:
        _echo_issues(issues)
    else:
        assert ledger is not None
        typer.echo(
            "Coverage ledger is valid: "
            f"{len(ledger.sources)} sources, "
            f"{sum(len(source.items) for source in ledger.sources)} items."
        )
    if issues:
        raise typer.Exit(1)


@coverage_app.command("show")
def show_command(
    ledger_path: Path | None = typer.Option(
        None,
        "--ledger",
        help="Show a local ledger instead of the packaged canonical ledger.",
    ),
    source_id: str | None = typer.Option(
        None,
        "--source",
        help="Filter by stable coverage source ID.",
    ),
    status: CoverageStatusFilter | None = typer.Option(
        None,
        "--status",
        help="Filter counted items by coverage status.",
    ),
    output_format: CoverageDisplayFormat = typer.Option(
        CoverageDisplayFormat.text,
        "--format",
        "-f",
        help="Output format: text, json.",
    ),
) -> None:
    """Show deterministic source summaries and counted-item evidence."""
    ledger, issues = _load_and_validate(ledger_path)
    if issues or ledger is None:
        _emit_failure(output_format, ledger, issues)
        raise typer.Exit(1)
    filtered, filter_issue = _filter_ledger(
        ledger,
        source_id=source_id,
        status=status.value if status is not None else None,
    )
    if filter_issue is not None:
        _emit_failure(output_format, ledger, (filter_issue,))
        raise typer.Exit(1)
    if output_format == CoverageDisplayFormat.json:
        typer.echo(_render_cli_json(filtered, (), include_items=True))
    else:
        typer.echo(render_coverage_markdown(filtered), nl=False)


@coverage_app.command("export")
def export_command(
    ledger_path: Path | None = typer.Option(
        None,
        "--ledger",
        help="Export a local ledger instead of the packaged canonical ledger.",
    ),
    export_format: CoverageExportFormat = typer.Option(
        CoverageExportFormat.markdown,
        "--format",
        "-f",
        help="Export format: markdown, json.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write to a file instead of stdout.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Atomically replace an existing regular output file.",
    ),
) -> None:
    """Export a deterministic Markdown or JSON ledger view."""
    ledger, issues = _load_and_validate(ledger_path)
    if issues or ledger is None:
        _emit_failure(
            (
                CoverageDisplayFormat.json
                if export_format == CoverageExportFormat.json
                else CoverageDisplayFormat.text
            ),
            ledger,
            issues,
        )
        raise typer.Exit(1)
    content = (
        render_coverage_markdown(ledger)
        if export_format == CoverageExportFormat.markdown
        else _render_cli_json(ledger, (), include_items=True)
    )
    if output is None:
        typer.echo(content, nl=False)
        return
    issue = write_coverage_output(output, content, force=force)
    if issue is not None:
        _emit_failure(
            (
                CoverageDisplayFormat.json
                if export_format == CoverageExportFormat.json
                else CoverageDisplayFormat.text
            ),
            ledger,
            (issue,),
        )
        raise typer.Exit(1)
    typer.echo(f"Wrote coverage export to {output}.")


def _load_and_validate(
    ledger_path: Path | None,
) -> tuple[CoverageLedger | None, tuple[CoverageLedgerIssue, ...]]:
    try:
        ledger = load_coverage_ledger(ledger_path)
    except CoverageLedgerLoadError as exc:
        return None, (exc.issue,)
    from webconf_audit.cli import _ensure_all_rules_loaded
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    return ledger, validate_coverage_ledger(ledger, registry)


def _filter_ledger(
    ledger: CoverageLedger,
    *,
    source_id: str | None,
    status: CoverageStatus | None,
) -> tuple[CoverageLedger, CoverageLedgerIssue | None]:
    sources = ledger.sources
    if source_id is not None:
        sources = tuple(source for source in sources if source.source_id == source_id)
        if not sources:
            return ledger, CoverageLedgerIssue(
                code="unknown_source_reference",
                message=f"Unknown coverage source: {source_id}",
                source_id=source_id,
            )
    if status is not None:
        sources = tuple(
            source.model_copy(
                update={
                    "items": tuple(
                        item for item in source.items if item.status == status
                    )
                }
            )
            for source in sources
        )
    return ledger.model_copy(update={"sources": sources}), None


def _repository_documentation_paths() -> tuple[Path, Path] | None:
    repo_root = Path(__file__).resolve().parents[3]
    tracker = repo_root / "docs" / "control-source-coverage-tracker.md"
    benchmark = repo_root / "docs" / "benchmarks-covering.md"
    if (repo_root / "pyproject.toml").is_file() and tracker.is_file() and benchmark.is_file():
        return tracker, benchmark
    return None


def _render_cli_json(
    ledger: CoverageLedger | None,
    issues: tuple[CoverageLedgerIssue, ...],
    *,
    include_items: bool,
) -> str:
    summaries = (
        {summary.source_id: summary for summary in summarize_coverage(ledger)}
        if ledger is not None
        else {}
    )
    sources: list[dict[str, object]] = []
    if ledger is not None:
        for source in ledger.sources:
            summary = summaries[source.source_id]
            payload: dict[str, object] = {
                "source_id": source.source_id,
                "title": source.title,
                "version": source.version,
                "summary": summary.model_dump(mode="json"),
            }
            if include_items:
                payload["items"] = [
                    item.model_dump(mode="json") for item in source.items
                ]
            sources.append(payload)
    return (
        json.dumps(
            {
                "schema_version": 1,
                "valid": not issues,
                "issues": [issue.model_dump(mode="json") for issue in issues],
                "sources": sources,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _emit_failure(
    output_format: CoverageDisplayFormat,
    ledger: CoverageLedger | None,
    issues: tuple[CoverageLedgerIssue, ...],
) -> None:
    if output_format == CoverageDisplayFormat.json:
        typer.echo(_render_cli_json(ledger, issues, include_items=False))
    else:
        _echo_issues(issues)


def _echo_issues(issues: tuple[CoverageLedgerIssue, ...]) -> None:
    for issue in issues:
        typer.echo(f"{issue.code}: {issue.message}", err=True)


__all__ = ["coverage_app"]
