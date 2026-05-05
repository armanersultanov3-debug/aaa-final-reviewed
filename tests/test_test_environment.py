from __future__ import annotations

import tempfile
from pathlib import Path


def test_python_tempdir_is_workspace_local() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    repo_tmp = (repo_root / ".tmp").resolve()
    tempdir = Path(tempfile.gettempdir()).resolve()

    assert tempdir == repo_tmp or repo_tmp in tempdir.parents


def test_pytest_tmp_path_is_workspace_local(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    repo_tmp = (repo_root / ".tmp").resolve()
    resolved_tmp_path = tmp_path.resolve()

    assert resolved_tmp_path == repo_tmp or repo_tmp in resolved_tmp_path.parents
