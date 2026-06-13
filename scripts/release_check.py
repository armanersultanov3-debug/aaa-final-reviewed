"""Build and smoke-test release artifacts before publishing."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from typing import Sequence
import zipfile


DEFAULT_WORK_DIR = Path(".tmp") / "release-check"
CHANGELOG_FILE = "CHANGELOG.md"
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
        project_version = _project_version(repo_root)
        print(f"==> Check release notes for current version: {CHANGELOG_FILE}", flush=True)
        _check_release_notes(repo_root, project_version)
        print("==> Validate source coverage ledger and documents", flush=True)
        _validate_source_coverage(repo_root)
        _run("Build wheel and sdist", ["uv", "build", "--out-dir", str(dist_dir)], cwd=repo_root)
        wheel = _select_single_artifact(dist_dir, "*.whl")
        sdist = _select_single_artifact(dist_dir, "*.tar.gz")
        _assert_coverage_ledger_packaged(wheel, sdist)
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
                _version_assertion_code(project_version),
            ],
        )
        _run(
            "Validate installed rule crosswalk",
            [
                str(venv_python),
                "-c",
                _installed_crosswalk_validation_code(),
            ],
        )
        _run(
            "Validate installed coverage ledger",
            [
                str(venv_python),
                "-c",
                _installed_coverage_validation_code(),
            ],
        )
        coverage_payload = _run_json(
            "Run installed coverage CLI validation",
            [str(console_script), "coverage", "validate", "--format", "json"],
        )
        _validate_coverage_payload(coverage_payload)
        catalog_payload = _run_json(
            "Load installed rule catalog",
            [str(console_script), "list-rules", "--format", "json"],
        )
        _validate_rule_catalog_payload(catalog_payload)
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
            "Check release notes for current version",
            "Validate source coverage ledger and documents",
            ["uv", "build", "--out-dir", str(dist_dir)],
            [sys.executable, "-m", "venv", str(venv_dir)],
            [str(venv_python), "-m", "pip", "install", "<built wheel>"],
            [str(venv_python), "-m", "pip", "check"],
            "Validate installed rule crosswalk",
            "Validate installed coverage ledger",
            ["webconf-audit", "coverage", "validate", "--format", "json"],
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
        print(f"{index}. {_format_plan_step(command)}")


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


def _validate_source_coverage(repo_root: Path) -> None:
    from webconf_audit.cli import _ensure_all_rules_loaded
    from webconf_audit.coverage_ledger import (
        check_coverage_documentation,
        load_coverage_ledger,
        validate_coverage_ledger,
    )
    from webconf_audit.crosswalk_integrity import validate_registry_crosswalk
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    ledger = load_coverage_ledger()
    crosswalk_issues = validate_registry_crosswalk(registry.list_rules())
    ledger_issues = validate_coverage_ledger(ledger, registry)
    documentation_issues = check_coverage_documentation(
        ledger,
        repo_root / "docs" / "control-source-coverage-tracker.md",
        repo_root / "docs" / "benchmarks-covering.md",
    )
    issues = (*crosswalk_issues, *ledger_issues, *documentation_issues)
    if issues:
        details = "\n".join(
            f"- {issue.code}: {issue.message}"
            for issue in issues
        )
        raise ReleaseCheckError(f"source coverage validation failed:\n{details}")


def _assert_coverage_ledger_packaged(wheel: Path, sdist: Path) -> None:
    wheel_member = "webconf_audit/data/control_source_coverage.yml"
    with zipfile.ZipFile(wheel) as archive:
        if wheel_member not in archive.namelist():
            raise ReleaseCheckError(
                f"built wheel is missing {wheel_member}"
            )
    with tarfile.open(sdist, "r:gz") as archive:
        names = archive.getnames()
        if not any(name.endswith(f"/{wheel_member}") for name in names):
            raise ReleaseCheckError(
                f"built sdist is missing {wheel_member}"
            )


def _validate_coverage_payload(payload: object) -> None:
    if not isinstance(payload, dict):
        raise ReleaseCheckError("coverage validation payload must be an object")
    if payload.get("schema_version") != 1:
        raise ReleaseCheckError("coverage validation payload has an invalid schema")
    if payload.get("valid") is not True:
        raise ReleaseCheckError(
            f"installed coverage ledger is invalid: {payload.get('issues')!r}"
        )
    if payload.get("issues") != []:
        raise ReleaseCheckError("valid coverage payload must have no issues")
    sources = payload.get("sources")
    if not isinstance(sources, list) or len(sources) != 8:
        raise ReleaseCheckError(
            "installed coverage ledger must contain the eight counted sources"
        )


def _validate_rule_catalog_payload(payload: object) -> None:
    if not isinstance(payload, list) or not payload:
        raise ReleaseCheckError("installed rule catalog must be a non-empty array")
    for entry in payload:
        if not isinstance(entry, dict):
            raise ReleaseCheckError("installed rule catalog contains a non-object entry")
        rule_id = str(entry.get("rule_id", "<unknown>"))
        for field_name in ("standards", "standards_secondary"):
            references = entry.get(field_name)
            if not isinstance(references, list):
                raise ReleaseCheckError(
                    f"{rule_id}: {field_name} must be an array"
                )
            for reference in references:
                if not isinstance(reference, dict):
                    raise ReleaseCheckError(
                        f"{rule_id}: {field_name} contains a non-object reference"
                    )
                if "origin" not in reference:
                    raise ReleaseCheckError(
                        f"{rule_id}: standard reference is missing origin"
                    )
                if "derived_from" not in reference:
                    raise ReleaseCheckError(
                        f"{rule_id}: standard reference is missing derived_from"
                    )
                origin = reference["origin"]
                derived_from = reference["derived_from"]
                if origin == "declared" and derived_from is not None:
                    raise ReleaseCheckError(
                        f"{rule_id}: declared reference has derived_from metadata"
                    )
                if origin == "derived" and field_name != "standards_secondary":
                    raise ReleaseCheckError(
                        f"{rule_id}: derived reference must use standards_secondary"
                    )
                if origin == "derived" and not (
                    isinstance(derived_from, dict)
                    and isinstance(derived_from.get("standard"), str)
                    and derived_from["standard"].strip()
                    and isinstance(derived_from.get("reference"), str)
                    and derived_from["reference"].strip()
                ):
                    raise ReleaseCheckError(
                        f"{rule_id}: derived reference has no complete source"
                    )
                if origin not in {"declared", "derived"}:
                    raise ReleaseCheckError(
                        f"{rule_id}: unsupported standard-reference origin {origin!r}"
                    )


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


def _check_release_notes(repo_root: Path, project_version: str) -> None:
    changelog = repo_root / CHANGELOG_FILE
    if not changelog.exists():
        raise ReleaseCheckError(f"{CHANGELOG_FILE} is missing")

    lines = changelog.read_text(encoding="utf-8").splitlines()
    header_index = _find_changelog_version_header(lines, project_version)
    if header_index is None:
        raise ReleaseCheckError(f"{CHANGELOG_FILE} has no section for version {project_version}")

    body: list[str] = []
    for line in lines[header_index + 1 :]:
        if line.startswith("## "):
            break
        body.append(line.strip())
    if not any(line and not line.startswith("<!--") for line in body):
        raise ReleaseCheckError(f"{CHANGELOG_FILE} section {project_version} is empty")


def _find_changelog_version_header(lines: Sequence[str], project_version: str) -> int | None:
    accepted_prefixes = (
        f"## [{project_version}]",
        f"## {project_version}",
    )
    for index, line in enumerate(lines):
        if any(line.startswith(prefix) for prefix in accepted_prefixes):
            return index
    return None


def _version_assertion_code(expected_version: str) -> str:
    return (
        "from importlib.metadata import version; "
        f"actual = version('webconf-audit'); "
        f"raise SystemExit(0 if actual == {expected_version!r} else "
        f"'expected webconf-audit {expected_version}, got ' + actual)"
    )


def _installed_crosswalk_validation_code() -> str:
    return (
        "from webconf_audit.cli import _ensure_all_rules_loaded; "
        "from webconf_audit.crosswalk_integrity import validate_registry_crosswalk; "
        "from webconf_audit.rule_registry import registry; "
        "_ensure_all_rules_loaded(); "
        "issues = validate_registry_crosswalk(registry.list_rules()); "
        "raise SystemExit(0 if not issues else "
        "'crosswalk validation failed: ' + '; '.join("
        "f'{issue.code}:{issue.rule_id or \"-\"}:{issue.reference or \"-\"}' "
        "for issue in issues))"
    )


def _installed_coverage_validation_code() -> str:
    return (
        "from webconf_audit.cli import _ensure_all_rules_loaded; "
        "from webconf_audit.coverage_ledger import "
        "load_coverage_ledger, validate_coverage_ledger; "
        "from webconf_audit.rule_registry import registry; "
        "_ensure_all_rules_loaded(); "
        "ledger = load_coverage_ledger(); "
        "issues = validate_coverage_ledger(ledger, registry); "
        "raise SystemExit(0 if not issues else "
        "'coverage validation failed: ' + '; '.join("
        "f'{issue.code}:{issue.source_id or \"-\"}:{issue.item_id or \"-\"}' "
        "for issue in issues))"
    )


def _format_command(command: Sequence[str]) -> str:
    return " ".join(_quote_part(part) for part in command)


def _format_plan_step(step: Sequence[str] | str) -> str:
    if isinstance(step, str):
        return step
    return _format_command(step)


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
