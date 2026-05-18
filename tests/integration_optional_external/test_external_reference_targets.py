from __future__ import annotations

import json
import os
import ssl
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


def _openssl_can_negotiate_tls_v1() -> bool:
    """OpenSSL 3.5 removed TLS 1.0/1.1 entirely; older builds keep it behind SECLEVEL."""
    return ssl.OPENSSL_VERSION_INFO[:2] < (3, 5)


pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_EXTERNAL_TESTS") != "1",
    reason="Set RUN_EXTERNAL_TESTS=1 to run safe external reference smoke tests.",
)


@pytest.mark.parametrize(
    "target",
    _load_targets(),
    ids=lambda t: t["id"],
)
def test_badssl_reference_target_matches_expected_categories(
    target: dict[str, Any],
) -> None:
    if target["id"] == "badssl-tls-v1-0" and not _openssl_can_negotiate_tls_v1():
        pytest.skip(
            f"Local {ssl.OPENSSL_VERSION} cannot negotiate TLS 1.0; "
            "legacy-protocol probe is impossible from this runtime."
        )

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
