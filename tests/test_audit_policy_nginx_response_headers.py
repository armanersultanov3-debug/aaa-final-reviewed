from __future__ import annotations

from pathlib import Path

from tests.nginx_response_header_policy_helpers import (
    api_response_profile,
    browser_document_profile,
    response_headers_policy_payload,
    response_route,
)
from tests.nginx_sensitive_location_policy_helpers import write_policy
from webconf_audit.coverage_ledger import load_coverage_ledger


def _load_registry():
    from webconf_audit.cli import _ensure_all_rules_loaded
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    return registry


def test_load_validate_and_resolve_policy_with_nginx_response_headers(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import (
        AuditTarget,
        load_audit_policy,
        resolve_audit_policy,
        validate_audit_policy,
    )

    payload = response_headers_policy_payload(
        routes=[
            response_route(
                route_id="app-html",
                server_names=("www.example.test",),
                profile="browser-document",
            )
        ]
    )
    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(write_policy(tmp_path, payload))

    assert validate_audit_policy(policy, ledger, registry) == ()

    resolved = resolve_audit_policy(
        policy,
        AuditTarget(
            mode="local",
            server_type="nginx",
            target=str(tmp_path / "nginx.conf"),
        ),
        ledger,
    )

    assert resolved.nginx is not None
    assert resolved.nginx.response_headers is not None
    assert resolved.nginx.response_headers.route_manifest[0].route_id == "app-html"
    assert "browser-document" in resolved.nginx.response_headers.profiles


def test_validate_policy_rejects_unknown_response_header_profile_reference(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    payload = response_headers_policy_payload(
        routes=[
            response_route(
                route_id="app-html",
                server_names=("www.example.test",),
                profile="missing-profile",
            )
        ],
        profiles={"browser-document": browser_document_profile()},
    )
    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(write_policy(tmp_path, payload))

    issues = validate_audit_policy(policy, ledger, registry)

    assert [issue.code for issue in issues] == [
        "unknown_nginx_response_header_profile_reference"
    ]


def test_validate_policy_rejects_overlapping_response_header_routes(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    payload = response_headers_policy_payload(
        routes=[
            response_route(
                route_id="app-html-a",
                server_names=("www.example.test",),
                profile="browser-document",
                sample_uris=("/",),
            ),
            response_route(
                route_id="app-html-b",
                server_names=("www.example.test",),
                profile="api-response",
                sample_uris=("/",),
                response_kind="api",
            ),
        ],
        profiles={
            "browser-document": browser_document_profile(),
            "api-response": api_response_profile(),
        },
    )
    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(write_policy(tmp_path, payload))

    issues = validate_audit_policy(policy, ledger, registry)

    assert [issue.code for issue in issues] == [
        "overlapping_nginx_response_header_routes"
    ]


def test_load_validate_and_resolve_policy_accepts_quoted_csp_hash_sources(
    tmp_path: Path,
) -> None:
    from webconf_audit.audit_policy import load_audit_policy, validate_audit_policy

    profile = browser_document_profile()
    profile["csp"]["script_authorization"] = {
        "mode": "hash",
        "allowed_nonce_variables": [],
        "allow_static_nonce": False,
        "allowed_hashes": [
            "'sha256-QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE='",
        ],
        "allow_host_allowlist_fallback": False,
        "require_strict_dynamic": False,
    }
    payload = response_headers_policy_payload(
        routes=[
            response_route(
                route_id="app-html",
                server_names=("www.example.test",),
                profile="browser-document",
            )
        ],
        profiles={"browser-document": profile},
    )
    ledger = load_coverage_ledger()
    registry = _load_registry()
    policy = load_audit_policy(write_policy(tmp_path, payload))

    assert validate_audit_policy(policy, ledger, registry) == ()
