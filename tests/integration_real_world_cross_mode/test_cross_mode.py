"""Cross-mode validation: same config audited locally and externally.

Each case in ``manifest.json`` describes a real-world web server config that
the test infrastructure brings up in a Docker container bound to a localhost
port. For every case we:

1. Run the matching local analyzer (``analyze-nginx``, ``analyze-apache``,
   ``analyze-lighttpd``) against the source config file shipped with the case.
2. Run ``analyze-external`` against ``http(s)://127.0.0.1:<port>/`` of the
   running container.
3. Assert that the expected local- and external-mode findings actually fire.
4. Cross-check that header-related local findings have matching external
   observations (e.g. local says ``missing_hsts_header`` -> external must say
   ``external.hsts_header_missing``).

The local and external analyzers are independent code paths in the project;
this is the closest thing to a black-box regression test for the whole
pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from webconf_audit.external import analyze_external_target
from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config


_TEST_DIR = Path(__file__).resolve().parent


_ANALYZERS = {
    "nginx": analyze_nginx_config,
    "apache": analyze_apache_config,
    "lighttpd": analyze_lighttpd_config,
}


# Cross-mode invariants: if the *local* analyzer flags the rule on the left,
# the *external* probe on the same container must observe the rule on the
# right. Both sides describe the same surface (response headers) so they
# cannot disagree on a well-behaved server.
_LOCAL_TO_EXTERNAL_HEADER_INVARIANTS: dict[str, str] = {
    "nginx.missing_hsts_header": "external.hsts_header_missing",
    "nginx.missing_x_frame_options": "external.x_frame_options_missing",
    "nginx.missing_x_content_type_options": "external.x_content_type_options_missing",
    "nginx.missing_content_security_policy": "external.content_security_policy_missing",
    "nginx.missing_referrer_policy": "external.referrer_policy_missing",
    "nginx.missing_permissions_policy": "external.permissions_policy_missing",
    "apache.missing_hsts_header": "external.hsts_header_missing",
    "apache.missing_x_frame_options_header": "external.x_frame_options_missing",
    "apache.missing_content_security_policy": "external.content_security_policy_missing",
    "apache.missing_referrer_policy_header": "external.referrer_policy_missing",
    "apache.missing_permissions_policy_header": "external.permissions_policy_missing",
    "lighttpd.missing_strict_transport_security": "external.hsts_header_missing",
    "lighttpd.missing_x_frame_options": "external.x_frame_options_missing",
    "lighttpd.missing_content_security_policy": "external.content_security_policy_missing",
    "lighttpd.missing_referrer_policy": "external.referrer_policy_missing",
}


def _case_id(case: dict[str, Any]) -> str:
    return str(case["id"])


def _load_cases() -> list[dict[str, Any]]:
    import json

    manifest = _TEST_DIR / "manifest.json"
    return list(json.loads(manifest.read_text(encoding="utf-8"))["cases"])


@pytest.mark.parametrize("case", _load_cases(), ids=_case_id)
def test_real_world_cross_mode_consistency(case: dict[str, Any]) -> None:
    server_type = case["server_type"]
    analyzer = _ANALYZERS[server_type]
    entry_path = _TEST_DIR / case["source_subdir"] / case["entry_config"]

    local_result = analyzer(str(entry_path))
    local_rule_ids = {finding.rule_id for finding in local_result.findings}

    fatal_local_issues = [
        issue for issue in local_result.issues
        if issue.level == "error"
    ]
    assert not fatal_local_issues, (
        f"{case['id']}: local analyzer reported fatal issues: {fatal_local_issues}"
    )

    for expected in case.get("expected_local_findings_subset", []):
        assert expected in local_rule_ids, (
            f"{case['id']}: local analyzer did not fire expected '{expected}'; "
            f"observed={sorted(local_rule_ids)}"
        )

    external_url = f"{case['scheme']}://127.0.0.1:{case['port']}/"
    external_result = analyze_external_target(external_url, scan_ports=False)
    external_rule_ids = {finding.rule_id for finding in external_result.findings}

    fatal_external_issues = [
        issue for issue in external_result.issues
        if issue.level == "error"
    ]
    assert not fatal_external_issues, (
        f"{case['id']}: external probe reported fatal issues: {fatal_external_issues}"
    )

    for expected in case.get("expected_external_findings_subset", []):
        assert expected in external_rule_ids, (
            f"{case['id']}: external analyzer did not fire expected '{expected}'; "
            f"observed={sorted(external_rule_ids)}"
        )

    # Header cross-mode invariants only apply to HTTPS endpoints because the
    # external missing-header rules deliberately ignore HTTP responses (HTTP
    # traffic is insecure regardless of headers, so the analyzer pushes the
    # focus toward enabling HTTPS first).
    if case["scheme"] == "https":
        violations: list[str] = []
        for local_rule, external_rule in _LOCAL_TO_EXTERNAL_HEADER_INVARIANTS.items():
            if local_rule in local_rule_ids and external_rule not in external_rule_ids:
                violations.append(
                    f"local '{local_rule}' fired but external '{external_rule}' did not"
                )
        assert not violations, (
            f"{case['id']}: cross-mode header invariants violated: {violations}"
        )
