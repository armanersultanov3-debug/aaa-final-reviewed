from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


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
    assert "Validate source coverage ledger and documents" in output
    assert "webconf-audit list-rules --format json" in output
    assert "Validate installed rule crosswalk" in output
    assert "Validate installed coverage ledger" in output
    assert "webconf-audit coverage validate --format json" in output
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


def test_rule_catalog_payload_requires_provenance_fields() -> None:
    module = _load_release_check_module()
    payload = [
        {
            "rule_id": "test.rule",
            "standards": [
                {
                    "standard": "OWASP ASVS",
                    "reference": "v5.0.0-3.4.2",
                    "coverage": "partial",
                }
            ],
            "standards_secondary": [],
        }
    ]

    with pytest.raises(module.ReleaseCheckError, match="origin"):
        module._validate_rule_catalog_payload(payload)


def test_rule_catalog_payload_accepts_declared_and_derived_references() -> None:
    module = _load_release_check_module()
    payload = [
        {
            "rule_id": "test.rule",
            "standards": [
                {
                    "standard": "OWASP Top 10",
                    "reference": "A05:2021",
                    "coverage": "direct",
                    "origin": "declared",
                    "derived_from": None,
                }
            ],
            "standards_secondary": [
                {
                    "standard": "OWASP Top 10",
                    "reference": "A02:2025",
                    "coverage": "direct",
                    "origin": "derived",
                    "derived_from": {
                        "standard": "OWASP Top 10",
                        "reference": "A05:2021",
                    },
                }
            ],
        }
    ]

    module._validate_rule_catalog_payload(payload)


def test_coverage_payload_accepts_valid_eight_source_result() -> None:
    module = _load_release_check_module()

    module._validate_coverage_payload(
        {
            "schema_version": 1,
            "valid": True,
            "issues": [],
            "sources": [{} for _ in range(8)],
        }
    )


def test_coverage_payload_rejects_invalid_result() -> None:
    module = _load_release_check_module()

    with pytest.raises(module.ReleaseCheckError, match="invalid"):
        module._validate_coverage_payload(
            {
                "schema_version": 1,
                "valid": False,
                "issues": [{"code": "summary_count_mismatch"}],
                "sources": [],
            }
        )


def test_rule_catalog_payload_rejects_derived_reference_in_primary_tier() -> None:
    module = _load_release_check_module()
    payload = [
        {
            "rule_id": "test.rule",
            "standards": [
                {
                    "standard": "OWASP Top 10",
                    "reference": "A02:2025",
                    "coverage": "direct",
                    "origin": "derived",
                    "derived_from": {
                        "standard": "OWASP Top 10",
                        "reference": "A05:2021",
                    },
                }
            ],
            "standards_secondary": [],
        }
    ]

    with pytest.raises(module.ReleaseCheckError, match="secondary"):
        module._validate_rule_catalog_payload(payload)


@pytest.mark.parametrize("source_value", ["", "   "])
def test_rule_catalog_payload_rejects_blank_derived_source(
    source_value: str,
) -> None:
    module = _load_release_check_module()
    payload = [
        {
            "rule_id": "test.rule",
            "standards": [],
            "standards_secondary": [
                {
                    "standard": "OWASP Top 10",
                    "reference": "A02:2025",
                    "coverage": "direct",
                    "origin": "derived",
                    "derived_from": {
                        "standard": source_value,
                        "reference": "A05:2021",
                    },
                }
            ],
        }
    ]

    with pytest.raises(module.ReleaseCheckError, match="complete source"):
        module._validate_rule_catalog_payload(payload)


def _load_release_check_module():
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "release_check.py"
    spec = importlib.util.spec_from_file_location("release_check_under_test", script)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
