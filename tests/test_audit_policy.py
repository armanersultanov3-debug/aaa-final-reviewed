from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from webconf_audit.cli import _ensure_all_rules_loaded
from webconf_audit.coverage_ledger import load_coverage_ledger


def _base_policy_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "public-web-baseline",
        "policy_version": "2026.06",
        "title": "Public web baseline",
        "description": "Required controls for public web services.",
        "defaults": {
            "disposition": "advisory",
            "evidence_expectation": "ledger-default",
            "include_unmapped_findings": True,
            "require_complete_execution_manifest": True,
        },
        "profiles": [
            {
                "profile_id": "public-nginx",
                "title": "Public nginx",
                "selectors": [
                    {
                        "mode": "local",
                        "server_type": "nginx",
                        "target_glob": "production/*",
                    }
                ],
                "requested_opt_in_tags": ["policy-review"],
                "sources": [
                    {
                        "source_id": "owasp-asvs-5.0.0",
                        "disposition": "required",
                        "controls": [
                            {
                                "item_id": "asvs-3.4.7-csp-reporting",
                                "disposition": "review",
                                "evidence_expectation": "operator-review",
                                "required_rule_ids": [
                                    "nginx.content_security_policy_missing_reporting_endpoint"
                                ],
                                "rationale": "Receiver ownership requires manual review.",
                            }
                        ],
                    }
                ],
            }
        ],
        "provenance": {
            "owner": "Security Engineering",
            "approved_on": "2026-06-12",
            "change_ref": "SEC-2026-104",
        },
    }


def _reverse_proxy_policy_payload() -> dict[str, object]:
    payload = _base_policy_payload()
    payload["nginx"] = {
        "reverse_proxy_headers": {
            "profiles": [
                {
                    "profile_id": "public-http",
                    "applies_to": {
                        "upstream_families": ["proxy"],
                        "server_names": ["example.test"],
                        "location_patterns": ["/api/"],
                    },
                    "request_headers": {
                        "required": {
                            "X-Forwarded-For": {
                                "any_of": ["$proxy_add_x_forwarded_for", "$remote_addr"]
                            },
                            "X-Real-IP": {"any_of": ["$remote_addr"]},
                            "X-Forwarded-Proto": {"any_of": ["$scheme"]},
                        },
                        "host": {
                            "allowed_values": ["$host", "$proxy_host"],
                            "allow_fixed_literals": True,
                        },
                        "forbidden_client_variables": [
                            "$http_x_forwarded_for",
                            "$http_x_real_ip",
                            "$http_host",
                        ],
                    },
                    "response_headers": {
                        "must_hide": ["X-Powered-By"],
                        "must_not_pass": ["Server"],
                        "allow_explicit_pass": [],
                    },
                }
            ],
            "unmatched_routes": "indeterminate",
        }
    }
    return payload


def _write_policy(tmp_path: Path, payload: dict[str, object]) -> Path:
    policy_path = tmp_path / ".webconf-audit-policy.yml"
    policy_path.write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )
    return policy_path


def _load_registry():
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    return registry


def test_load_validate_and_resolve_policy_happy_path(tmp_path: Path) -> None:
    from webconf_audit.audit_policy import (
        AuditTarget,
        load_audit_policy,
        requested_opt_in_tags,
        resolve_audit_policy,
        validate_audit_policy,
    )

    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(_write_policy(tmp_path, _base_policy_payload()))
    issues = validate_audit_policy(policy, ledger, registry)

    assert issues == ()

    resolved = resolve_audit_policy(
        policy,
        AuditTarget(
            mode="local",
            server_type="nginx",
            target="production/edge-01",
        ),
        ledger,
    )

    assert resolved.policy_id == "public-web-baseline"
    assert resolved.profile_id == "public-nginx"
    assert requested_opt_in_tags(resolved) == frozenset({"policy-review"})
    assert resolved.raw_sha256
    assert resolved.resolved_sha256
    asvs_source = next(
        source for source in resolved.sources if source.source_id == "owasp-asvs-5.0.0"
    )
    overridden = next(
        control
        for control in asvs_source.controls
        if control.item_id == "asvs-3.4.7-csp-reporting"
    )
    assert overridden.disposition == "review"
    assert overridden.evidence_expectation == "operator-review"
    assert (
        "nginx.content_security_policy_missing_reporting_endpoint"
        in overridden.required_rule_ids
    )


def test_load_validate_and_resolve_policy_with_reverse_proxy_headers(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditTarget, load_audit_policy, resolve_audit_policy, validate_audit_policy

    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(_write_policy(tmp_path, _reverse_proxy_policy_payload()))

    assert validate_audit_policy(policy, ledger, registry) == ()

    resolved = resolve_audit_policy(
        policy,
        AuditTarget(
            mode="local",
            server_type="nginx",
            target="production/edge-01",
        ),
        ledger,
    )

    assert resolved.nginx is not None
    assert resolved.nginx.reverse_proxy_headers is not None
    profile = resolved.nginx.reverse_proxy_headers.profiles[0]
    assert profile.profile_id == "public-http"
    assert profile.request_headers.host is not None
    assert profile.response_headers.must_hide == ("X-Powered-By",)


def test_validate_policy_rejects_conflicting_reverse_proxy_response_headers(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    payload = _reverse_proxy_policy_payload()
    payload["nginx"]["reverse_proxy_headers"]["profiles"][0]["response_headers"] = {  # type: ignore[index]
        "must_hide": ["Server"],
        "must_not_pass": [],
        "allow_explicit_pass": ["server"],
    }

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(_write_policy(tmp_path, payload))

    assert excinfo.value.issue.code == "policy_schema_invalid"


def test_validate_policy_rejects_overlapping_reverse_proxy_profiles(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    payload = _reverse_proxy_policy_payload()
    payload["nginx"]["reverse_proxy_headers"]["profiles"].append(  # type: ignore[index]
        {
            "profile_id": "public-http-alt",
            "applies_to": {
                "upstream_families": ["proxy"],
                "server_names": ["example.test"],
                "location_patterns": ["/api/"],
            },
            "request_headers": {
                "required": {
                    "X-Forwarded-For": {"any_of": ["$remote_addr"]},
                },
                "host": {
                    "allowed_values": ["$host"],
                    "allow_fixed_literals": False,
                },
                "forbidden_client_variables": ["$http_host"],
            },
            "response_headers": {
                "must_hide": ["X-Powered-By"],
                "must_not_pass": [],
                "allow_explicit_pass": [],
            },
        }
    )

    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(_write_policy(tmp_path, payload))
    issues = validate_audit_policy(policy, ledger, registry)

    assert [issue.code for issue in issues] == ["overlapping_nginx_reverse_proxy_profiles"]


def test_resolve_policy_expands_inherited_defaults_for_selected_source(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import AuditTarget, load_audit_policy, resolve_audit_policy

    payload = _base_policy_payload()
    payload["profiles"] = [
        {
            "profile_id": "nginx-all-cis",
            "title": "All CIS nginx controls",
            "selectors": [
                {
                    "mode": "local",
                    "server_type": "nginx",
                    "target_glob": "configs/*",
                }
            ],
            "sources": [
                {
                    "source_id": "cis-nginx-3.0.0",
                    "disposition": "required",
                    "controls": [],
                }
            ],
        }
    ]

    ledger = load_coverage_ledger()
    policy = load_audit_policy(_write_policy(tmp_path, payload))
    resolved = resolve_audit_policy(
        policy,
        AuditTarget(mode="local", server_type="nginx", target="configs/edge-01"),
        ledger,
    )
    source = next(source for source in resolved.sources if source.source_id == "cis-nginx-3.0.0")
    applicable_count = sum(
        1
        for ledger_source in ledger.sources
        if ledger_source.source_id == "cis-nginx-3.0.0"
        for item in ledger_source.items
        if item.applicability == "applicable"
    )

    assert len(source.controls) == applicable_count
    assert {control.inherited_from for control in source.controls} == {"source"}
    assert {control.disposition for control in source.controls} == {"required"}


def test_validate_policy_rejects_unsafe_yaml(tmp_path: Path) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    policy_path = tmp_path / ".webconf-audit-policy.yml"
    policy_path.write_text(
        "schema_version: 1\n"
        "policy_id: sample\n"
        "policy_version: '1'\n"
        "title: Sample\n"
        "description: Sample\n"
        "defaults: &defaults\n"
        "  disposition: advisory\n"
        "  evidence_expectation: ledger-default\n"
        "profiles:\n"
        "  - <<: *defaults\n",
        encoding="utf-8",
    )

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(policy_path)

    assert excinfo.value.issue.code == "policy_yaml_invalid"


def test_load_audit_policy_reports_stat_oserror_as_load_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from webconf_audit.audit_policy import AuditPolicyLoadError, load_audit_policy

    policy_path = _write_policy(tmp_path, _base_policy_payload())
    path_type = type(policy_path)
    original_stat = path_type.stat

    def _failing_stat(self: Path):
        if self == policy_path:
            raise OSError("stat failed")
        return original_stat(self)

    monkeypatch.setattr(path_type, "stat", _failing_stat)

    with pytest.raises(AuditPolicyLoadError) as excinfo:
        load_audit_policy(policy_path)

    assert excinfo.value.issue.code == "policy_file_not_found"
    assert "could not be read" in excinfo.value.issue.message


def test_validate_policy_rejects_derived_direct_owasp_expectation(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    payload = _base_policy_payload()
    payload["profiles"] = [
        {
            "profile_id": "owasp-2025-nginx",
            "title": "OWASP 2025 nginx",
            "selectors": [
                {
                    "mode": "local",
                    "server_type": "nginx",
                    "target_glob": "production/*",
                }
            ],
            "sources": [
                {
                    "source_id": "owasp-top10-2025",
                    "disposition": "required",
                    "controls": [
                        {
                            "item_id": "owasp-top10-a02-2025-security-misconfiguration",
                            "disposition": "required",
                            "evidence_expectation": "declared-direct",
                            "required_rule_ids": ["nginx.hsts_header_unsafe"],
                            "rationale": "Attempt to require direct proof.",
                        }
                    ],
                }
            ],
        }
    ]

    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(_write_policy(tmp_path, payload))
    issues = validate_audit_policy(policy, ledger, registry)

    assert [issue.code for issue in issues] == ["derived_rule_cannot_satisfy_direct"]
    assert issues[0].item_id == "owasp-top10-a02-2025-security-misconfiguration"
    assert issues[0].rule_id == "nginx.hsts_header_unsafe"


def test_validate_policy_rejects_unknown_opt_in_tag(tmp_path: Path) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    payload = _base_policy_payload()
    payload["profiles"][0]["requested_opt_in_tags"] = ["policy-review", "unknown-tag"]  # type: ignore[index]

    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(_write_policy(tmp_path, payload))
    issues = validate_audit_policy(policy, ledger, registry)

    assert {issue.code for issue in issues} == {"unknown_opt_in_tag"}


def test_resolve_policy_requires_exactly_one_matching_profile(tmp_path: Path) -> None:
    from webconf_audit.audit_policy import (
        AuditPolicyResolveError,
        AuditTarget,
        load_audit_policy,
        resolve_audit_policy,
    )

    payload = _base_policy_payload()
    payload["profiles"] = [
        {
            "profile_id": "first-nginx",
            "title": "First nginx",
            "selectors": [
                {"mode": "local", "server_type": "nginx", "target_glob": "prod/*"}
            ],
            "sources": [{"source_id": "cis-nginx-3.0.0"}],
        },
        {
            "profile_id": "second-nginx",
            "title": "Second nginx",
            "selectors": [
                {"mode": "local", "server_type": "nginx", "target_glob": "prod/*"}
            ],
            "sources": [{"source_id": "owasp-asvs-5.0.0"}],
        },
    ]

    ledger = load_coverage_ledger()
    policy = load_audit_policy(_write_policy(tmp_path, payload))

    with pytest.raises(AuditPolicyResolveError) as overlap:
        resolve_audit_policy(
            policy,
            AuditTarget(mode="local", server_type="nginx", target="prod/edge-01"),
            ledger,
        )
    assert overlap.value.issue.code == "multiple_matching_profiles"

    with pytest.raises(AuditPolicyResolveError) as missing:
        resolve_audit_policy(
            policy,
            AuditTarget(mode="local", server_type="apache", target="prod/httpd-01"),
            ledger,
        )
    assert missing.value.issue.code == "no_matching_profile"


def test_resolve_policy_target_glob_does_not_cross_path_segments(tmp_path: Path) -> None:
    from webconf_audit.audit_policy import (
        AuditPolicyResolveError,
        AuditTarget,
        load_audit_policy,
        resolve_audit_policy,
    )

    payload = _base_policy_payload()
    payload["profiles"] = [
        {
            "profile_id": "segmented-nginx",
            "title": "Segmented nginx",
            "selectors": [
                {
                    "mode": "local",
                    "server_type": "nginx",
                    "target_glob": "configs/*/nginx.conf",
                }
            ],
            "sources": [{"source_id": "cis-nginx-3.0.0"}],
        }
    ]

    ledger = load_coverage_ledger()
    policy = load_audit_policy(_write_policy(tmp_path, payload))
    resolved = resolve_audit_policy(
        policy,
        AuditTarget(
            mode="local",
            server_type="nginx",
            target="configs/edge/nginx.conf",
        ),
        ledger,
    )

    assert resolved.profile_id == "segmented-nginx"

    with pytest.raises(AuditPolicyResolveError) as excinfo:
        resolve_audit_policy(
            policy,
            AuditTarget(
                mode="local",
                server_type="nginx",
                target="configs/edge/extra/nginx.conf",
            ),
            ledger,
        )

    assert excinfo.value.issue.code == "no_matching_profile"


def test_resolved_policy_hash_is_deterministic(tmp_path: Path) -> None:
    from webconf_audit.audit_policy import AuditTarget, load_audit_policy, resolve_audit_policy

    ledger = load_coverage_ledger()
    policy_path = _write_policy(tmp_path, _base_policy_payload())

    first = resolve_audit_policy(
        load_audit_policy(policy_path),
        AuditTarget(mode="local", server_type="nginx", target="production/edge-01"),
        ledger,
    )
    second = resolve_audit_policy(
        load_audit_policy(policy_path),
        AuditTarget(mode="local", server_type="nginx", target="production/edge-01"),
        ledger,
    )

    assert first.raw_sha256 == second.raw_sha256
    assert first.resolved_sha256 == second.resolved_sha256
    assert json.dumps(first.model_dump(mode="json"), sort_keys=True) == json.dumps(
        second.model_dump(mode="json"),
        sort_keys=True,
    )
