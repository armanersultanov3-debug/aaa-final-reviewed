"""Build and smoke-test release artifacts before publishing."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence


DEFAULT_WORK_DIR = Path(".tmp") / "release-check"
IIS_SMOKE_FIXTURE = (
    Path("tests")
    / "fixtures"
    / "webserver-configs"
    / "iis"
    / "secure"
    / "cis-hardened-baseline.config"
)


class ReleaseCheckError(RuntimeError):
    """Raised when the release check cannot continue."""


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    work_dir = _resolve_inside_repo(repo_root, args.work_dir)

    if args.dry_run:
        _print_dry_run_plan(work_dir)
        return 0

    _prepare_work_dir(repo_root, work_dir)
    dist_dir = work_dir / "dist"
    venv_dir = work_dir / "venv"

    try:
        _run("Build wheel and sdist", ["uv", "build", "--out-dir", str(dist_dir)], cwd=repo_root)
        wheel = _select_single_artifact(dist_dir, "*.whl")
        _select_single_artifact(dist_dir, "*.tar.gz")
        _run("Create clean virtual environment", [args.python, "-m", "venv", str(venv_dir)])

        venv_python = _venv_python(venv_dir)
        console_script = _venv_console_script(venv_dir)
        _run("Install built wheel", [str(venv_python), "-m", "pip", "install", str(wheel)])
        _run("Check installed dependencies", [str(venv_python), "-m", "pip", "check"])
        _run(
            "Check installed package version",
            [
                str(venv_python),
                "-c",
                _version_assertion_code(_project_version(repo_root)),
            ],
        )
        _run_json(
            "Load installed rule catalog",
            [str(console_script), "list-rules", "--format", "json"],
        )
        _run_json(
            "Run installed IIS smoke analysis",
            [
                str(console_script),
                "analyze-iis",
                str(repo_root / IIS_SMOKE_FIXTURE),
                "--no-tls-registry",
                "--format",
                "json",
            ],
        )
    except ReleaseCheckError as exc:
        print(f"release-check failed: {exc}", file=sys.stderr)
        return 1

    print(f"release-check passed. Artifacts are in {dist_dir}")
    return 0


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build wheel/sdist artifacts and smoke-test the installed CLI.",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=DEFAULT_WORK_DIR,
        help="Workspace-local directory for dist artifacts and the smoke-test venv.",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable used to create the smoke-test virtual environment.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the release-check plan without running commands.",
    )
    return parser.parse_args(argv)


def _print_dry_run_plan(work_dir: Path) -> None:
    dist_dir = work_dir / "dist"
    venv_dir = work_dir / "venv"
    venv_python = _venv_python(venv_dir)
    print("Release check plan:")
    for index, command in enumerate(
        [
            ["uv", "build", "--out-dir", str(dist_dir)],
            [sys.executable, "-m", "venv", str(venv_dir)],
            [str(venv_python), "-m", "pip", "install", "<built wheel>"],
            [str(venv_python), "-m", "pip", "check"],
            ["webconf-audit", "list-rules", "--format", "json"],
            [
                "webconf-audit",
                "analyze-iis",
                str(IIS_SMOKE_FIXTURE),
                "--no-tls-registry",
                "--format",
                "json",
            ],
        ],
        start=1,
    ):
        print(f"{index}. {_format_command(command)}")


def _resolve_inside_repo(repo_root: Path, work_dir: Path) -> Path:
    resolved = (repo_root / work_dir).resolve() if not work_dir.is_absolute() else work_dir.resolve()
    repo_resolved = repo_root.resolve()
    if resolved == repo_resolved or not resolved.is_relative_to(repo_resolved):
        raise SystemExit("--work-dir must point to a directory inside the repository.")
    return resolved


def _prepare_work_dir(repo_root: Path, work_dir: Path) -> None:
    if work_dir.exists():
        _remove_workspace_dir(repo_root, work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)


def _remove_workspace_dir(repo_root: Path, path: Path) -> None:
    resolved = path.resolve()
    repo_resolved = repo_root.resolve()
    if resolved == repo_resolved or not resolved.is_relative_to(repo_resolved):
        raise ReleaseCheckError(f"refusing to remove path outside repository: {resolved}")
    shutil.rmtree(resolved)


def _run(
    label: str,
    command: Sequence[str],
    *,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"==> {label}: {_format_command(command)}", flush=True)
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=_command_env(),
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ReleaseCheckError(f"command not found: {command[0]}") from exc
    if result.returncode != 0:
        raise ReleaseCheckError(f"{label} exited with {result.returncode}")
    return result


def _run_json(label: str, command: Sequence[str]) -> object:
    print(f"==> {label}: {_format_command(command)}", flush=True)
    try:
        result = subprocess.run(
            list(command),
            capture_output=True,
            env=_command_env(),
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ReleaseCheckError(f"command not found: {command[0]}") from exc
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        raise ReleaseCheckError(f"{label} exited with {result.returncode}")
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReleaseCheckError(f"{label} did not produce valid JSON") from exc
    if not parsed:
        raise ReleaseCheckError(f"{label} produced an empty JSON payload")
    return parsed


def _select_single_artifact(dist_dir: Path, pattern: str) -> Path:
    artifacts = sorted(dist_dir.glob(pattern))
    if len(artifacts) != 1:
        names = ", ".join(artifact.name for artifact in artifacts) or "none"
        raise ReleaseCheckError(
            f"expected exactly one {pattern} artifact in {dist_dir}, found {names}"
        )
    return artifacts[0]


def _venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _venv_console_script(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "webconf-audit.exe"
    return venv_dir / "bin" / "webconf-audit"


def _project_version(repo_root: Path) -> str:
    pyproject = repo_root / "pyproject.toml"
    in_project = False
    for raw_line in pyproject.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "[project]":
            in_project = True
            continue
        if in_project and line.startswith("["):
            break
        if in_project and line.startswith("version"):
            _, value = line.split("=", 1)
            return value.strip().strip('"')
    raise ReleaseCheckError("could not read project.version from pyproject.toml")


def _version_assertion_code(expected_version: str) -> str:
    return (
        "from importlib.metadata import version; "
        f"actual = version('webconf-audit'); "
        f"raise SystemExit(0 if actual == {expected_version!r} else "
        f"'expected webconf-audit {expected_version}, got ' + actual)"
    )


def _format_command(command: Sequence[str]) -> str:
    return " ".join(_quote_part(part) for part in command)


def _command_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def _quote_part(part: str) -> str:
    if not part:
        return '""'
    if any(char.isspace() for char in part):
        return f'"{part}"'
    return part


if __name__ == "__main__":
    raise SystemExit(main())
