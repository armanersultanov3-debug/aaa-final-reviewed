from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


def test_release_check_dry_run_lists_packaging_smoke_steps() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "release_check.py"

    result = subprocess.run(
        [sys.executable, str(script), "--dry-run"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    output = result.stdout
    assert "Release check plan:" in output
    assert "uv build --out-dir" in output
    assert "-m venv" in output
    assert "-m pip install" in output
    assert "Check release notes for current version" in output
    assert "webconf-audit list-rules --format json" in output
    assert "webconf-audit analyze-iis" in output
    assert "--no-tls-registry --format json" in output


def test_release_notes_check_rejects_missing_current_version_section(tmp_path: Path) -> None:
    module = _load_release_check_module()
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [1.2.2] - 2026-06-04\n\n- Previous release.\n",
        encoding="utf-8",
    )

    try:
        module._check_release_notes(tmp_path, "1.2.3")
    except module.ReleaseCheckError as exc:
        assert "has no section for version 1.2.3" in str(exc)
    else:
        raise AssertionError("missing changelog version section was accepted")


def test_release_notes_check_rejects_empty_current_version_section(tmp_path: Path) -> None:
    module = _load_release_check_module()
    (tmp_path / "CHANGELOG.md").write_text(
        (
            "# Changelog\n\n"
            "## [1.2.3] - 2026-06-05\n\n"
            "## [1.2.2] - 2026-06-04\n\n"
            "- Previous.\n"
        ),
        encoding="utf-8",
    )

    try:
        module._check_release_notes(tmp_path, "1.2.3")
    except module.ReleaseCheckError as exc:
        assert "section 1.2.3 is empty" in str(exc)
    else:
        raise AssertionError("empty changelog version section was accepted")


def _load_release_check_module():
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "release_check.py"
    spec = importlib.util.spec_from_file_location("release_check_under_test", script)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
