from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from webconf_audit.cli import app
from webconf_audit.models import AnalysisResult

runner = CliRunner()


def _write_config(tmp_path: Path) -> Path:
    path = tmp_path / "httpd.conf"
    path.write_text(
        "ServerTokens Prod\n"
        "LoadModule authz_core_module modules/mod_authz_core.so\n"
        "LoadModule ssl_module modules/mod_ssl.so\n",
        encoding="utf-8",
    )
    return path


def _write_snapshot(tmp_path: Path) -> Path:
    path = tmp_path / "apache-modules.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "apache-module-inventory",
                "snapshot_id": "prod-web-01-20260612",
                "host": "prod-web-01",
                "captured_at": "2026-06-12T08:00:00Z",
                "apache": {
                    "version": "2.4.63",
                    "configuration_id": "sha256:demo-config",
                },
                "completeness": {
                    "state": "complete",
                    "basis": "operator-export-of-effective-loaded-modules",
                },
                "modules": [
                    {
                        "name": "authz_core_module",
                        "state": "loaded",
                        "linkage": "static",
                        "source": "runtime-snapshot",
                    },
                    {
                        "name": "ssl_module",
                        "state": "loaded",
                        "linkage": "shared",
                        "source": "runtime-snapshot",
                    },
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


def test_analyze_apache_cli_passes_module_inventory_option(tmp_path: Path, monkeypatch) -> None:
    config_path = _write_config(tmp_path)
    snapshot_path = _write_snapshot(tmp_path)
    captured: dict[str, object] = {}

    def fake_analyze(config_path_arg: str, **kwargs: object) -> AnalysisResult:
        captured["config_path"] = config_path_arg
        captured.update(kwargs)
        return AnalysisResult(
            mode="local",
            target=config_path_arg,
            server_type="apache",
            metadata={"apache_module_inventory": {"snapshot": {"snapshot_id": "prod-web-01-20260612"}}},
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze)

    result = runner.invoke(
        app,
        [
            "analyze-apache",
            str(config_path),
            "--module-inventory",
            str(snapshot_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["config_path"] == str(config_path)
    assert captured["module_inventory_path"] == str(snapshot_path)
    payload = json.loads(result.stdout)
    assert payload["results"][0]["metadata"]["apache_module_inventory"]["snapshot"]["snapshot_id"] == "prod-web-01-20260612"


def test_analyze_apache_cli_invalid_module_inventory_exits_1_before_analyzer_runs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    snapshot_path = tmp_path / "apache-modules.json"
    snapshot_path.write_text("{bad json", encoding="utf-8")
    called = False

    def fake_analyze(_config_path: str, **_kwargs: object) -> AnalysisResult:
        nonlocal called
        called = True
        return AnalysisResult(mode="local", target=_config_path, server_type="apache")

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze)

    result = runner.invoke(
        app,
        [
            "analyze-apache",
            str(config_path),
            "--module-inventory",
            str(snapshot_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    assert called is False
    assert "apache_module_snapshot_invalid" in result.stdout


def test_analyze_apache_cli_semantically_invalid_inventory_exits_1_before_analyzer_runs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    snapshot_path = tmp_path / "apache-modules.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "apache-module-inventory",
                "snapshot_id": "prod-web-01-20260612",
                "host": "prod-web-01",
                "captured_at": "2026-06-12T08:00:00Z",
                "apache": {
                    "version": "2.4.63",
                    "configuration_id": "sha256:demo-config",
                },
                "completeness": {
                    "state": "complete",
                    "basis": "operator-export-of-effective-loaded-modules",
                },
                "modules": [
                    {
                        "name": "ssl_module",
                        "state": "loaded",
                        "linkage": "shared",
                        "source": "runtime-snapshot",
                    },
                    {
                        "name": "mod_ssl.c",
                        "state": "absent",
                        "linkage": "unknown",
                        "source": "complete-snapshot-absence",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    called = False

    def fake_analyze(_config_path: str, **_kwargs: object) -> AnalysisResult:
        nonlocal called
        called = True
        return AnalysisResult(mode="local", target=_config_path, server_type="apache")

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze)

    result = runner.invoke(
        app,
        [
            "analyze-apache",
            str(config_path),
            "--module-inventory",
            str(snapshot_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    assert called is False
    assert "apache_module_snapshot_invalid" in result.stdout
    assert "conflicting state" in result.stdout
