from __future__ import annotations

from tests.external_helpers import (
    _http_redirect_probe,
    _https_probe_with_headers,
    _server_identification,
    run_external_rules,
)

_RULE_ID = "external.iis.server_header_removal_not_applied"


def test_iis_native_server_header_rule_fires_with_iis_fingerprint() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="Microsoft-IIS/10.0"),
        _http_redirect_probe(server_header="Microsoft-IIS/10.0"),
    ]

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=_server_identification("iis", "high"),
    )

    matched = [finding for finding in findings if finding.rule_id == _RULE_ID]
    assert len(matched) == 2
    assert matched[0].location.details == "Server: Microsoft-IIS/10.0"
    assert matched[0].metadata["observation_source"] == "runtime_server_header"
    assert matched[0].metadata["complementary_rule_id"] == (
        "iis.request_filtering_remove_server_header_disabled"
    )


def test_iis_native_server_header_rule_ignores_missing_server_header() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header=None),
        _http_redirect_probe(server_header=None),
    ]

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=_server_identification("iis", "high"),
    )

    assert _RULE_ID not in {finding.rule_id for finding in findings}


def test_iis_native_server_header_rule_is_conservative_on_header_mismatch() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="nginx/1.21"),
        _http_redirect_probe(server_header="nginx/1.21"),
    ]

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=_server_identification("iis", "high"),
    )

    assert _RULE_ID not in {finding.rule_id for finding in findings}
