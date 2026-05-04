from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from webconf_audit.external import analyze_external_target


_ROOT = Path(__file__).resolve().parents[2]
_TARGETS_PATH = (
    _ROOT
    / "tests"
    / "fixtures"
    / "webserver-configs"
    / "external-targets"
    / "badssl.json"
)


def _load_targets() -> list[dict[str, Any]]:
    payload = json.loads(_TARGETS_PATH.read_text(encoding="utf-8"))
    targets = payload.get("targets")
    assert isinstance(targets, list)
    return targets


pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_EXTERNAL_TESTS") != "1",
    reason="Set RUN_EXTERNAL_TESTS=1 to run safe external reference smoke tests.",
)


def test_badssl_reference_targets_match_expected_categories() -> None:
    for target in _load_targets():
        result = analyze_external_target(target["url"], scan_ports=False)
        observed = {finding.rule_id: finding for finding in result.findings}

        assert result.mode == "external"
        assert result.target == target["url"]
        assert isinstance(result.findings, list)
        assert isinstance(result.issues, list)

        for expected in target["expected_findings"]:
            rule_id = expected["rule_id"]
            assert rule_id in observed, (
                f"{target['id']} did not produce expected {rule_id}; "
                f"observed={sorted(observed)}"
            )
            assert observed[rule_id].severity == expected["severity"]
