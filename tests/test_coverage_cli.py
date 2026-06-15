"""CLI contract tests for the machine-readable coverage ledger."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import yaml
from typer.testing import CliRunner

import webconf_audit.cli
import webconf_audit.cli.coverage as coverage_cli
from webconf_audit.cli import app
from webconf_audit.coverage_ledger import load_coverage_ledger

runner = CliRunner()


def test_coverage_validate_text_succeeds() -> None:
    result = runner.invoke(app, ["coverage", "validate"])

    assert result.exit_code == 0, result.output
    assert "Coverage ledger is valid" in result.stdout
    assert "8 sources" in result.stdout
    assert "110 items" in result.stdout


def test_coverage_validate_json_has_stable_top_level_shape() -> None:
    result = runner.invoke(app, ["coverage", "validate", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert set(payload) == {"schema_version", "valid", "issues", "sources"}
    assert payload["schema_version"] == 1
    assert payload["valid"] is True
    assert payload["issues"] == []
    assert len(payload["sources"]) == 8


def test_coverage_validate_json_reports_schema_failure(tmp_path: Path) -> None:
    ledger = tmp_path / "invalid.yml"
    ledger.write_text("schema_version: 2\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "coverage",
            "validate",
            "--ledger",
            str(ledger),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert payload["issues"][0]["code"] == "ledger_schema_unsupported"


def test_coverage_show_filters_source_and_status() -> None:
    result = runner.invoke(
        app,
        [
            "coverage",
            "show",
            "--source",
            "cis-nginx-3.0.0",
            "--status",
            "policy-review",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert len(payload["sources"]) == 1
    source = payload["sources"][0]
    assert source["source_id"] == "cis-nginx-3.0.0"
    assert [entry["status"] for entry in source["items"]] == ["policy-review"]


def test_coverage_show_rejects_unknown_source() -> None:
    result = runner.invoke(
        app,
        ["coverage", "show", "--source", "does-not-exist"],
    )

    assert result.exit_code == 1
    assert "Unknown coverage source" in result.stderr


def test_coverage_export_writes_markdown_and_refuses_overwrite(
    tmp_path: Path,
) -> None:
    output = tmp_path / "coverage.md"

    first = runner.invoke(
        app,
        [
            "coverage",
            "export",
            "--format",
            "markdown",
            "--output",
            str(output),
        ],
    )
    second = runner.invoke(
        app,
        [
            "coverage",
            "export",
            "--format",
            "markdown",
            "--output",
            str(output),
        ],
    )

    assert first.exit_code == 0, first.output
    assert output.read_text(encoding="utf-8").startswith("<!-- Generated from ")
    assert second.exit_code == 1
    assert "already exists" in second.stderr


def test_coverage_export_force_overwrites_existing_file(tmp_path: Path) -> None:
    output = tmp_path / "coverage.json"
    output.write_text("stale", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "coverage",
            "export",
            "--format",
            "json",
            "--output",
            str(output),
            "--force",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["valid"] is True


def test_coverage_reconcile_check_text_succeeds() -> None:
    result = runner.invoke(app, ["coverage", "reconcile", "--check"])

    assert result.exit_code == 0, result.output
    assert "Coverage reconciliation is clean" in result.stdout
    assert "3 tracked artifacts" in result.stdout


def test_coverage_reconcile_check_json_has_stable_top_level_shape() -> None:
    result = runner.invoke(
        app,
        ["coverage", "reconcile", "--check", "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert set(payload) == {
        "artifacts",
        "issues",
        "schema_version",
        "sources",
        "valid",
    }
    assert payload["schema_version"] == 1
    assert payload["valid"] is True
    assert payload["issues"] == []
    assert len(payload["sources"]) == 8
    assert [artifact["label"] for artifact in payload["artifacts"]] == [
        "coverage-tracker",
        "benchmarks-snapshot",
        "standards-roadmap-final-reconciliation",
    ]


def test_coverage_reconcile_rejects_conflicting_modes() -> None:
    result = runner.invoke(app, ["coverage", "reconcile", "--check", "--write"])

    assert result.exit_code == 2
    assert "Choose exactly one of --check or --write." in result.stderr


def test_coverage_reconcile_check_passes_repo_root(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        coverage_cli,
        "_load_and_validate",
        lambda ledger_path: (object(), ()),
    )
    monkeypatch.setattr(webconf_audit.cli, "_ensure_all_rules_loaded", lambda: None)

    def fake_reconcile(ledger, registry, *, repo_root=None):
        captured["reconciliation_repo_root"] = repo_root
        return SimpleNamespace(artifacts=[object()], sources=[])

    def fake_check(ledger, registry, *, repo_root=None, compare_tracked=True):
        captured["check_repo_root"] = repo_root
        return ()

    monkeypatch.setattr(
        coverage_cli,
        "reconcile_coverage_documents",
        fake_reconcile,
    )
    monkeypatch.setattr(
        coverage_cli,
        "check_coverage_reconciliation",
        fake_check,
    )

    result = runner.invoke(
        app,
        [
            "coverage",
            "reconcile",
            "--check",
            "--repo-root",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["reconciliation_repo_root"] == tmp_path
    assert captured["check_repo_root"] == tmp_path


def test_coverage_validate_detects_semantic_summary_drift(
    tmp_path: Path,
) -> None:
    payload = load_coverage_ledger().model_dump(mode="json")
    payload["sources"][0]["expected_summary"]["full"] = 0
    ledger = tmp_path / "drift.yml"
    ledger.write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "coverage",
            "validate",
            "--ledger",
            str(ledger),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    result_payload = json.loads(result.stdout)
    assert "summary_count_mismatch" in {
        issue["code"] for issue in result_payload["issues"]
    }


def test_coverage_validate_detects_repository_documentation_drift(
    tmp_path: Path,
    monkeypatch,
) -> None:
    tracker = tmp_path / "tracker.md"
    benchmark = tmp_path / "benchmark.md"
    tracker.write_text("stale\n", encoding="utf-8")
    benchmark.write_text("stale\n", encoding="utf-8")
    monkeypatch.setattr(
        coverage_cli,
        "_repository_documentation_paths",
        lambda: (tracker, benchmark),
    )

    result = runner.invoke(
        app,
        ["coverage", "validate", "--format", "json"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert {issue["code"] for issue in payload["issues"]} == {
        "benchmark_summary_drift",
        "tracker_render_drift",
    }
