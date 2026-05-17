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
from webconf_audit.models import AnalysisResult, Finding
from webconf_audit.rule_registry import registry


_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_ROOT = (_ROOT / "tests" / "fixtures" / "rule-corpus").resolve()
_MANIFEST_PATH = _FIXTURE_ROOT / "manifest.json"
_LOCAL_SERVER_TYPES = frozenset({"nginx", "apache", "lighttpd", "iis"})
_RULE_PACKAGES = (
    "webconf_audit.local.nginx.rules",
    "webconf_audit.local.apache.rules",
    "webconf_audit.local.lighttpd.rules",
    "webconf_audit.local.iis.rules",
    "webconf_audit.local.rules.universal",
)


def _load_manifest() -> dict[str, Any]:
    payload = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    cases = payload.get("cases")
    assert isinstance(cases, list)
    return payload


_MANIFEST = _load_manifest()
_CASES: list[dict[str, Any]] = _MANIFEST["cases"]


def _case_id(case: dict[str, Any]) -> str:
    return str(case["id"])


def _string_list_field(
    case: dict[str, Any],
    field_name: str,
    *,
    required: bool = True,
) -> list[str]:
    case_id = case.get("id", "<unknown>")
    if field_name not in case:
        if required:
            raise AssertionError(f"{case_id} missing {field_name}")
        return []

    value = case[field_name]
    assert isinstance(value, list), f"{case_id} {field_name} must be a list"
    assert all(isinstance(item, str) for item in value), (
        f"{case_id} {field_name} must contain only strings"
    )
    return value


def _entrypoint(case: dict[str, Any]) -> Path:
    return _fixture_path(str(case["entrypoint"]), field_name="entrypoint")


def _fixture_path(value: str, *, field_name: str) -> Path:
    candidate = (_FIXTURE_ROOT / value).resolve()
    try:
        candidate.relative_to(_FIXTURE_ROOT)
    except ValueError as exc:
        raise AssertionError(
            f"rule corpus {field_name} escapes fixture root: {value!r}"
        ) from exc
    return candidate


def _analyze_case(case: dict[str, Any]) -> AnalysisResult:
    entrypoint = _entrypoint(case)
    server_type = case["server_type"]
    options = dict(case.get("analyzer_options", {}))

    if server_type == "nginx":
        return analyze_nginx_config(str(entrypoint))
    if server_type == "apache":
        return analyze_apache_config(str(entrypoint))
    if server_type == "lighttpd":
        host = options.get("host")
        return analyze_lighttpd_config(str(entrypoint), host=host)
    if server_type == "iis":
        tls_registry_path = options.get("tls_registry_path")
        if tls_registry_path is not None:
            tls_registry_path = str(
                _fixture_path(str(tls_registry_path), field_name="tls_registry_path")
            )
        return analyze_iis_config(
            str(entrypoint),
            tls_registry_path=tls_registry_path,
            use_tls_registry=bool(options.get("use_tls_registry", False)),
        )

    raise AssertionError(f"unsupported rule corpus server_type: {server_type!r}")


def _finding_by_rule_id(result: AnalysisResult) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in result.findings:
        grouped.setdefault(finding.rule_id, []).append(finding)
    return grouped


def _observed_rule_ids(result: AnalysisResult) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def _local_universal_rule_ids() -> set[str]:
    for package in _RULE_PACKAGES:
        registry.ensure_loaded(package)
    return {
        meta.rule_id
        for meta in registry.list_rules(category="local")
        if meta.server_type in _LOCAL_SERVER_TYPES
        and "policy-review" not in meta.tags
    } | {
        meta.rule_id
        for meta in registry.list_rules(category="universal")
        if "policy-review" not in meta.tags
    }


def test_rule_corpus_metadata_shape() -> None:
    assert _MANIFEST["scope"] == ["local", "universal"]
    assert _MANIFEST["excluded_scope"] == ["external"]

    profile_counts = Counter(case["profile"] for case in _CASES)
    server_counts = Counter(case["server_type"] for case in _CASES)
    id_counts = Counter(case["id"] for case in _CASES)
    duplicate_ids = sorted(
        case_id for case_id, count in id_counts.items() if count > 1
    )

    assert duplicate_ids == [], f"duplicate rule corpus case ids: {duplicate_ids}"
    assert profile_counts["hybrid-vulnerable"] >= 4
    assert profile_counts["targeted-vulnerable"] >= 12
    assert server_counts == {
        "nginx": 5,
        "apache": 7,
        "lighttpd": 6,
        "iis": 6,
    }


@pytest.mark.parametrize("case", _CASES, ids=_case_id)
def test_rule_corpus_metadata_entries_are_complete(case: dict[str, Any]) -> None:
    for key in (
        "id",
        "server_type",
        "profile",
        "description",
        "entrypoint",
        "provenance",
        "references",
        "expected_findings",
    ):
        assert key in case, f"{case.get('id', '<unknown>')} missing {key}"

    assert case["server_type"] in _LOCAL_SERVER_TYPES
    assert case["profile"] in {"hybrid-vulnerable", "targeted-vulnerable"}
    assert case["provenance"] in {"synthetic-derived", "synthetic-targeted"}
    _string_list_field(case, "references")
    _string_list_field(case, "expected_findings")
    _string_list_field(case, "allowed_issue_codes", required=False)
    _string_list_field(case, "expected_absent_rule_ids", required=False)
    assert _entrypoint(case).is_file()

    options = case.get("analyzer_options", {})
    if "tls_registry_path" in options:
        assert _fixture_path(
            str(options["tls_registry_path"]),
            field_name="tls_registry_path",
        ).is_file()


@pytest.mark.parametrize("case", _CASES, ids=_case_id)
def test_rule_corpus_expected_findings_are_detected(case: dict[str, Any]) -> None:
    result = _analyze_case(case)
    grouped_findings = _finding_by_rule_id(result)
    observed_ids = _observed_rule_ids(result)
    allowed_issue_codes = set(
        _string_list_field(case, "allowed_issue_codes", required=False)
    )

    assert result.mode == "local"
    assert result.server_type == case["server_type"]
    assert Path(result.target).resolve() == _entrypoint(case)
    assert not any(issue.level == "error" for issue in result.issues)
    assert not [
        issue
        for issue in result.issues
        if issue.level == "warning" and issue.code not in allowed_issue_codes
    ]

    for rule_id in _string_list_field(case, "expected_findings"):
        assert rule_id in grouped_findings, (
            f"{case['id']} did not produce expected {rule_id}; "
            f"observed={sorted(observed_ids)}"
        )

    for absent_rule_id in _string_list_field(
        case, "expected_absent_rule_ids", required=False
    ):
        assert absent_rule_id not in observed_ids, (
            f"{case['id']} unexpectedly produced {absent_rule_id}; "
            f"observed={sorted(observed_ids)}"
        )


def test_rule_corpus_covers_every_local_and_universal_rule() -> None:
    expected_rule_ids = _local_universal_rule_ids()
    covered_rule_ids = {
        rule_id
        for case in _CASES
        for rule_id in _string_list_field(case, "expected_findings")
    }

    assert covered_rule_ids <= expected_rule_ids
    assert expected_rule_ids - covered_rule_ids == set()
