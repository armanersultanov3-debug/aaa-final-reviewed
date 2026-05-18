from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest


_ROOT = Path(__file__).resolve().parents[2]
_TEST_DIR = Path(__file__).resolve().parent
_COMPOSE_FILE = _TEST_DIR / "docker-compose.yml"
_MANIFEST = _TEST_DIR / "manifest.json"
_PROJECT_NAME = "webconf_audit_real_world_cross_mode_it"
_DOCKER_PROBE_TIMEOUT_SECONDS = 5
# `docker compose up --build` for 11 services from cold cache routinely takes
# a minute or more on a slow runner; cap it generously so a stuck build still
# fails loudly instead of pinning the test session forever.
_COMPOSE_RUN_TIMEOUT_SECONDS = 900


def _load_cases() -> list[dict[str, Any]]:
    return list(json.loads(_MANIFEST.read_text(encoding="utf-8"))["cases"])


def _ready_url_for_case(case: dict[str, Any]) -> tuple[str, bool]:
    scheme = case["scheme"]
    port = case["port"]
    return (f"{scheme}://127.0.0.1:{port}/", scheme == "https")


def _docker_command() -> str | None:
    return shutil.which("docker")


def _compose_command() -> list[str] | None:
    docker_command = _docker_command()
    if docker_command is not None:
        try:
            compose_result = subprocess.run(
                [docker_command, "compose", "version"],
                cwd=_ROOT,
                text=True,
                capture_output=True,
                timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            compose_result = None
        if compose_result is not None and compose_result.returncode == 0:
            return [docker_command, "compose"]

    docker_compose_command = shutil.which("docker-compose")
    if docker_compose_command is None:
        return None

    try:
        compose_result = subprocess.run(
            [docker_compose_command, "version"],
            cwd=_ROOT,
            text=True,
            capture_output=True,
            timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if compose_result.returncode != 0:
        return None
    return [docker_compose_command]


def _run_compose(*args: str) -> subprocess.CompletedProcess[str]:
    if _COMPOSE_COMMAND is None:
        raise RuntimeError(_DOCKER_SKIP_REASON)
    return subprocess.run(
        [*_COMPOSE_COMMAND, "-p", _PROJECT_NAME, "-f", str(_COMPOSE_FILE), *args],
        cwd=_ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=_COMPOSE_RUN_TIMEOUT_SECONDS,
    )


def _docker_available() -> bool:
    if _COMPOSE_COMMAND is None:
        return False
    try:
        result = subprocess.run(
            [*_COMPOSE_COMMAND, "-p", _PROJECT_NAME, "-f", str(_COMPOSE_FILE), "ps"],
            cwd=_ROOT,
            text=True,
            capture_output=True,
            timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


_COMPOSE_COMMAND = _compose_command()
_DOCKER_AVAILABLE = _docker_available()
_DOCKER_SKIP_REASON = (
    "Docker Engine with docker compose support is required for "
    "real-world cross-mode integration tests"
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if _DOCKER_AVAILABLE:
        return
    skip = pytest.mark.skip(reason=_DOCKER_SKIP_REASON)
    for item in items:
        item.add_marker(skip)


def _wait_for_url(url: str, *, insecure_https: bool, timeout_seconds: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    context = ssl._create_unverified_context() if insecure_https else None

    last_error: str | None = None
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(request, timeout=2.0, context=context) as response:
                if response.status < 500:
                    return
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return
            last_error = str(exc)
        except OSError as exc:
            last_error = str(exc)
        time.sleep(0.5)

    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


@pytest.fixture(scope="session", autouse=True)
def real_world_cross_mode_stack() -> Generator[None, None, None]:
    if not _DOCKER_AVAILABLE:
        yield
        return
    _run_compose("down", "-v", "--remove-orphans")
    up = _run_compose("up", "-d", "--build")
    if up.returncode != 0:
        raise RuntimeError(
            f"docker compose up failed:\nSTDOUT:\n{up.stdout}\nSTDERR:\n{up.stderr}"
        )

    try:
        for case in _load_cases():
            url, insecure_https = _ready_url_for_case(case)
            _wait_for_url(url, insecure_https=insecure_https)
        yield
    finally:
        down = _run_compose("down", "-v", "--remove-orphans")
        if down.returncode != 0:
            raise RuntimeError(
                f"docker compose down failed:\n"
                f"STDOUT:\n{down.stdout}\nSTDERR:\n{down.stderr}"
            )


@pytest.fixture(scope="session")
def cases() -> list[dict[str, Any]]:
    return _load_cases()
