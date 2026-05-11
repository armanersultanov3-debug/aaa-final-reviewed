"""Focused regression tests for rule-standards mapping helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

import webconf_audit.rule_standards as rule_standards


def test_known_rule_ids_warns_when_rule_coverage_doc_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    fake_module = tmp_path / "src" / "webconf_audit" / "rule_standards.py"
    fake_module.parent.mkdir(parents=True)
    fake_module.write_text("# stub\n", encoding="utf-8")

    rule_standards._known_rule_ids.cache_clear()
    monkeypatch.setattr(rule_standards, "__file__", str(fake_module))

    with caplog.at_level("WARNING"):
        assert rule_standards._known_rule_ids() == frozenset()

    assert "rule-coverage.md is missing" in caplog.text

    rule_standards._known_rule_ids.cache_clear()


def test_direct_iso_references_do_not_apply_catch_all_to_unknown_rule() -> None:
    refs = rule_standards._iso_references("test.rule")

    assert all(ref.reference != "8.27" for ref in refs)


def test_direct_fstec_references_do_not_apply_catch_all_to_unknown_rule() -> None:
    refs = rule_standards._fstec_references("test.rule")

    assert all(ref.reference != "ЗИС.32" for ref in refs)
