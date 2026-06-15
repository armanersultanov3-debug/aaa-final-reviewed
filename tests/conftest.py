from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_TEST_TEMP_ROOT = _REPO_ROOT / ".tmp" / "python-temp"
_TEST_TEMP_ROOT.mkdir(parents=True, exist_ok=True)

for _env_name in ("TMPDIR", "TEMP", "TMP"):
    os.environ[_env_name] = str(_TEST_TEMP_ROOT)

tempfile.tempdir = str(_TEST_TEMP_ROOT)


def _workspace_mkdtemp(
    suffix: str | None = None,
    prefix: str | None = None,
    dir: str | os.PathLike[str] | None = None,
) -> str:
    parent = Path(dir) if dir is not None else _TEST_TEMP_ROOT
    parent.mkdir(parents=True, exist_ok=True)
    name_prefix = "tmp" if prefix is None else prefix
    name_suffix = "" if suffix is None else suffix

    for _attempt in range(100):
        candidate = parent / f"{name_prefix}{uuid.uuid4().hex}{name_suffix}"
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        return str(candidate)

    raise FileExistsError(f"Could not create unique test temp directory under {parent}")


tempfile.mkdtemp = _workspace_mkdtemp


@pytest.fixture
def tmp_path(request: pytest.FixtureRequest) -> Path:
    test_root = _TEST_TEMP_ROOT / "tmp_path"
    path = Path(
        _workspace_mkdtemp(
            prefix=f"{request.node.name[:24]}-",
            dir=test_root,
        )
    )
    try:
        yield path
    finally:
        resolved = path.resolve()
        allowed = test_root.resolve()
        if resolved == allowed or allowed not in resolved.parents:
            raise RuntimeError(f"Refusing to remove temp path outside {allowed}: {resolved}")
        shutil.rmtree(resolved, ignore_errors=True)


@pytest.fixture(autouse=True)
def _disable_ambient_iis_live_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep IIS tests independent from the developer/CI Windows registry."""
    from webconf_audit.local.iis import registry as iis_registry

    original_read_live_schannel = iis_registry.read_live_schannel
    original_read_live_registry = iis_registry.read_live_registry

    monkeypatch.setattr(
        iis_registry,
        "read_live_schannel",
        lambda reader=None: (
            original_read_live_schannel(reader) if reader is not None else (None, [])
        ),
    )
    monkeypatch.setattr(
        iis_registry,
        "read_live_registry",
        lambda reader=None: (
            original_read_live_registry(reader) if reader is not None else (None, [])
        ),
    )


@pytest.fixture(autouse=True)
def _disable_unknown_host_runtime_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep unit tests from performing live unknown-Host follow-up probes."""
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_unknown_host_responses",
        lambda _successful_attempts: [],
    )
