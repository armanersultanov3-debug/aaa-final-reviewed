from __future__ import annotations

from pathlib import Path

from tests.nginx_sensitive_location_policy_helpers import (
    resolved_sensitive_location_policy,
    sensitive_location_entry,
    sensitive_locations_policy_payload,
)
from webconf_audit.local.nginx import analyze_nginx_config


def _assessment(result, control_id: str, *, entry_id: str):
    matches = [
        entry
        for entry in result.control_assessments
        if entry.control_id == control_id and entry.metadata["catalog_entry_id"] == entry_id
    ]
    assert matches, (control_id, entry_id)
    assert len(matches) == 1, (control_id, entry_id)
    return matches[0]


def _matching_assessments(result, control_id: str, *, entry_id: str):
    return [
        entry
        for entry in result.control_assessments
        if entry.control_id == control_id and entry.metadata["catalog_entry_id"] == entry_id
    ]


def test_sensitive_location_policy_emits_pass_for_exact_ip_and_auth_contract(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location ^~ /admin/ {\n"
        "            allow 10.20.0.0/16;\n"
        "            deny all;\n"
        "            auth_request /authz;\n"
        "            satisfy all;\n"
        "        }\n"
        "        location = /authz {\n"
        "            internal;\n"
        "            return 204;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_sensitive_location_policy(
        tmp_path,
        sensitive_locations_policy_payload(
            catalog=[sensitive_location_entry()],
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    generic = _assessment(
        result,
        "policy.nginx.sensitive-location.admin-console",
        entry_id="admin-console",
    )
    cis = _assessment(
        result,
        "cis-nginx-5.1.1.sensitive-ip-filters",
        entry_id="admin-console",
    )

    assert generic.status == "pass"
    assert generic.metadata["policy_section"] == "nginx.sensitive_locations"
    assert generic.metadata["effective_satisfy"] == "all"
    assert cis.status == "pass"


def test_sensitive_location_policy_can_fail_generic_contract_while_cis_ip_control_passes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location ^~ /admin/ {\n"
        "            allow 10.20.0.0/16;\n"
        "            deny all;\n"
        "            satisfy all;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_sensitive_location_policy(
        tmp_path,
        sensitive_locations_policy_payload(
            catalog=[sensitive_location_entry()],
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    generic = _assessment(
        result,
        "policy.nginx.sensitive-location.admin-console",
        entry_id="admin-console",
    )
    cis = _assessment(
        result,
        "cis-nginx-5.1.1.sensitive-ip-filters",
        entry_id="admin-console",
    )

    assert generic.status == "fail"
    assert cis.status == "pass"


def test_sensitive_location_policy_omits_cis_assessment_when_ip_filter_is_optional(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location ^~ /admin/ {\n"
        "            auth_request /authz;\n"
        "            satisfy any;\n"
        "        }\n"
        "        location = /authz {\n"
        "            internal;\n"
        "            return 204;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_sensitive_location_policy(
        tmp_path,
        sensitive_locations_policy_payload(
            catalog=[
                sensitive_location_entry(
                    required_controls={
                        "one_of": [
                            {
                                "ip_allowlist": {
                                    "allowed_cidrs": ["10.20.0.0/16"],
                                    "require_deny_all_fallback": True,
                                }
                            },
                            {"auth_request": {}},
                        ],
                        "satisfy": "any",
                    },
                )
            ],
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    generic = _assessment(
        result,
        "policy.nginx.sensitive-location.admin-console",
        entry_id="admin-console",
    )

    assert generic.status == "pass"
    assert _matching_assessments(
        result,
        "cis-nginx-5.1.1.sensitive-ip-filters",
        entry_id="admin-console",
    ) == []


def test_sensitive_location_policy_marks_shadowed_sample_as_indeterminate(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location /admin/ {\n"
        "            allow 10.20.0.0/16;\n"
        "            deny all;\n"
        "            auth_request /authz;\n"
        "            satisfy all;\n"
        "        }\n"
        "        location ~ ^/admin/users$ {\n"
        "            allow all;\n"
        "        }\n"
        "        location = /authz {\n"
        "            internal;\n"
        "            return 204;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_sensitive_location_policy(
        tmp_path,
        sensitive_locations_policy_payload(
            catalog=[
                sensitive_location_entry(
                    declared_location={
                        "modifier": "prefix",
                        "pattern": "/admin/",
                    },
                    sample_uris=("/admin/users",),
                )
            ],
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)
    generic = _assessment(
        result,
        "policy.nginx.sensitive-location.admin-console",
        entry_id="admin-console",
    )

    assert generic.status == "indeterminate"
    assert generic.metadata["shadowed_samples"]


def test_sensitive_location_policy_keeps_builtin_findings_without_suppression(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        server_name example.test;\n"
        "        location /admin/ { }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_sensitive_location_policy(
        tmp_path,
        sensitive_locations_policy_payload(
            catalog=[sensitive_location_entry()],
        ),
    )

    no_policy_result = analyze_nginx_config(str(config_path))
    policy_result = analyze_nginx_config(str(config_path), policy=policy)

    assert {finding.rule_id for finding in policy_result.findings} == {
        finding.rule_id for finding in no_policy_result.findings
    }
    assert "nginx.missing_access_restrictions_on_sensitive_locations" in {
        finding.rule_id for finding in policy_result.findings
    }
    assert _assessment(
        policy_result,
        "policy.nginx.sensitive-location.admin-console",
        entry_id="admin-console",
    ).status == "fail"
