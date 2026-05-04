from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.models import AnalysisResult


_ROOT = Path(__file__).resolve().parents[1]
_DATASET_ROOT = _ROOT / "demo" / "real_world_configs"
_METADATA_PATH = _DATASET_ROOT / "metadata.json"


def _load_samples() -> list[dict[str, Any]]:
    payload = json.loads(_METADATA_PATH.read_text(encoding="utf-8"))
    samples = payload.get("samples")
    assert isinstance(samples, list)
    return samples


_SAMPLES = _load_samples()


def _sample_id(sample: dict[str, Any]) -> str:
    return str(sample["id"])


def _entrypoint(sample: dict[str, Any]) -> Path:
    return (_DATASET_ROOT / str(sample["entrypoint"])).resolve()


def _dataset_path(value: object) -> str:
    return str((_DATASET_ROOT / str(value)).resolve())


def _analyze_sample(sample: dict[str, Any]) -> AnalysisResult:
    entrypoint = _entrypoint(sample)
    server_type = sample["server_type"]
    analyzer_options = sample.get("analyzer_options", {})
    assert isinstance(analyzer_options, dict)

    if server_type == "nginx":
        return analyze_nginx_config(str(entrypoint))
    if server_type == "apache":
        return analyze_apache_config(str(entrypoint))
    if server_type == "lighttpd":
        host = analyzer_options.get("host")
        return analyze_lighttpd_config(str(entrypoint), host=host)
    if server_type == "iis":
        kwargs: dict[str, object] = {"use_tls_registry": False}
        machine_config = analyzer_options.get("machine_config")
        if machine_config is not None:
            kwargs["machine_config_path"] = _dataset_path(machine_config)
        return analyze_iis_config(str(entrypoint), **kwargs)

    raise AssertionError(f"unsupported server_type in real-world metadata: {server_type!r}")


def test_real_world_metadata_covers_expected_server_mix() -> None:
    counts = Counter(sample["server_type"] for sample in _SAMPLES)

    assert 2 <= counts["nginx"] <= 4
    assert 2 <= counts["apache"] <= 4
    assert 1 <= counts["lighttpd"] <= 3
    assert 1 <= counts["iis"] <= 3


@pytest.mark.parametrize("sample", _SAMPLES, ids=_sample_id)
def test_real_world_metadata_entries_are_complete(sample: dict[str, Any]) -> None:
    for key in (
        "id",
        "source_name",
        "source_url",
        "server_type",
        "license",
        "origin",
        "why_useful",
        "features",
        "entrypoint",
    ):
        assert sample.get(key)

    assert sample["origin"] in {"copied", "derived"}
    assert _entrypoint(sample).is_file()
    assert isinstance(sample["features"], list)
    assert sample["features"]
    assert isinstance(sample.get("expected_rule_ids", []), list)


@pytest.mark.parametrize("sample", _SAMPLES, ids=_sample_id)
def test_real_world_fixture_analyzers_do_not_crash(sample: dict[str, Any]) -> None:
    result = _analyze_sample(sample)
    entrypoint = _entrypoint(sample)

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == sample["server_type"]
    assert Path(result.target).resolve() == entrypoint
    assert isinstance(result.findings, list)
    assert isinstance(result.issues, list)
    assert not any(issue.level == "error" for issue in result.issues)

    observed_rule_ids = {finding.rule_id for finding in result.findings}
    expected_rule_ids = set(sample.get("expected_rule_ids", []))
    assert expected_rule_ids <= observed_rule_ids
