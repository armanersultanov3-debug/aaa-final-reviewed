from __future__ import annotations

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
    assert "webconf-audit list-rules --format json" in output
    assert "webconf-audit analyze-iis" in output
    assert "--no-tls-registry --format json" in output
