from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.models import AnalysisResult, Finding


_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_ROOT = (_ROOT / "tests" / "fixtures" / "webserver-configs").resolve()
_METADATA_PATH = _FIXTURE_ROOT / "metadata" / "cases.json"
_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _load_cases() -> list[dict[str, Any]]:
    payload = json.loads(_METADATA_PATH.read_text(encoding="utf-8"))
    cases = payload.get("cases")
    assert isinstance(cases, list)
    return cases


_CASES = _load_cases()


def _case_id(case: dict[str, Any]) -> str:
    return str(case["id"])


def _entrypoint(case: dict[str, Any]) -> Path:
    candidate = (_FIXTURE_ROOT / str(case["entrypoint"])).resolve()
    try:
        candidate.relative_to(_FIXTURE_ROOT)
    except ValueError as exc:
        raise AssertionError(
            f"security corpus entrypoint escapes fixture root: {case['entrypoint']!r}"
        ) from exc
    return candidate


def _analyze_case(case: dict[str, Any]) -> AnalysisResult:
    entrypoint = _entrypoint(case)
    server_type = case["server_type"]
    if server_type == "nginx":
        return analyze_nginx_config(str(entrypoint))
    if server_type == "apache":
        return analyze_apache_config(str(entrypoint))
    raise AssertionError(f"unsupported security corpus server_type: {server_type!r}")


def _finding_by_rule_id(result: AnalysisResult) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in result.findings:
        grouped.setdefault(finding.rule_id, []).append(finding)
    return grouped


def _observed_rule_ids(result: AnalysisResult) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def _finding_location_text(finding: Finding) -> str:
    location = finding.location
    if location is None:
        return ""
    return " ".join(
        str(value)
        for value in (
            location.file_path,
            location.line,
            location.xml_path,
            location.details,
        )
        if value is not None
    )


def test_security_corpus_metadata_covers_vulnerable_and_secure_cases() -> None:
    profile_counts = Counter(case["profile"] for case in _CASES)
    server_counts = Counter(case["server_type"] for case in _CASES)

    assert profile_counts["vulnerable"] >= 6
    assert profile_counts["secure"] >= 2
    assert server_counts["nginx"] >= 4
    assert server_counts["apache"] >= 4


@pytest.mark.parametrize("case", _CASES, ids=_case_id)
def test_security_corpus_metadata_entries_are_complete(case: dict[str, Any]) -> None:
    for key in (
        "id",
        "server_type",
        "profile",
        "source",
        "source_url",
        "license",
        "description",
        "entrypoint",
        "synthetic_or_original",
        "notes_about_modifications",
        "references",
        "expected_findings",
    ):
        assert key in case, f"{case.get('id', '<unknown>')} missing {key}"

    for key in (
        "id",
        "server_type",
        "profile",
        "source",
        "source_url",
        "license",
        "description",
        "entrypoint",
        "synthetic_or_original",
        "notes_about_modifications",
    ):
        assert case[key], f"{case.get('id', '<unknown>')} has empty {key}"

    assert case["profile"] in {"vulnerable", "secure", "edge-case"}
    assert case["synthetic_or_original"] in {"original", "synthetic-derived"}
    assert isinstance(case["references"], list)
    assert isinstance(case["expected_findings"], list)
    assert _entrypoint(case).is_file()


@pytest.mark.parametrize("case", _CASES, ids=_case_id)
def test_security_corpus_expected_findings_are_detected(case: dict[str, Any]) -> None:
    result = _analyze_case(case)
    grouped_findings = _finding_by_rule_id(result)
    observed_ids = _observed_rule_ids(result)

    assert result.mode == "local"
    assert result.server_type == case["server_type"]
    assert Path(result.target).resolve() == _entrypoint(case)
    assert isinstance(result.findings, list)
    assert isinstance(result.issues, list)
    assert not any(issue.level == "error" for issue in result.issues)

    for expected in case["expected_findings"]:
        rule_id = expected["rule_id"]
        assert rule_id in grouped_findings, (
            f"{case['id']} did not produce expected {rule_id}; "
            f"observed={sorted(observed_ids)}"
        )

        candidates = grouped_findings[rule_id]
        expected_severity = expected.get("severity")
        if expected_severity is not None:
            assert any(f.severity == expected_severity for f in candidates), (
                f"{case['id']} produced {rule_id}, but not with severity "
                f"{expected_severity}; observed={[f.severity for f in candidates]}"
            )

        title_contains = expected.get("title_contains")
        if title_contains is not None:
            assert any(title_contains in f.title for f in candidates)

        location_contains = expected.get("location_contains")
        if location_contains is not None:
            assert any(location_contains in _finding_location_text(f) for f in candidates)

    for absent_rule_id in case.get("expected_absent_rule_ids", []):
        assert absent_rule_id not in observed_ids, (
            f"{case['id']} unexpectedly produced {absent_rule_id}; "
            f"observed={sorted(observed_ids)}"
        )


@pytest.mark.parametrize(
    "case",
    [case for case in _CASES if case["profile"] == "secure"],
    ids=_case_id,
)
def test_secure_baseline_cases_do_not_emit_high_or_critical_findings(
    case: dict[str, Any],
) -> None:
    result = _analyze_case(case)
    blocking = [
        finding
        for finding in result.findings
        if _SEVERITY_RANK[finding.severity] >= _SEVERITY_RANK["high"]
    ]

    assert blocking == []
