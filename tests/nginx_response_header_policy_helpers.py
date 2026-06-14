from __future__ import annotations

from pathlib import Path

from tests.nginx_logging_policy_helpers import base_policy_payload, resolved_policy


def response_route(
    *,
    route_id: str,
    server_names: tuple[str, ...],
    profile: str,
    response_kind: str = "html_document",
    schemes: tuple[str, ...] = ("https",),
    expected_statuses: tuple[int, ...] = (200, 500),
    declared_location: dict[str, object] | None = None,
    sample_uris: tuple[str, ...] = ("/",),
) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": route_id,
        "server_names": list(server_names),
        "response_kind": response_kind,
        "schemes": list(schemes),
        "expected_statuses": list(expected_statuses),
        "profile": profile,
    }
    if declared_location is not None:
        payload["declared_location"] = declared_location
    if sample_uris:
        payload["sample_uris"] = list(sample_uris)
    return payload


def browser_document_profile(
    *,
    conditional_branches: str = "require_all",
    csp_enforcement_required: bool = True,
) -> dict[str, object]:
    return {
        "conditional_branches": conditional_branches,
        "csp": {
            "enforcement": {
                "required": csp_enforcement_required,
                "baseline_policy": "any_enforcing",
                "additional_policies": "require_parseable",
            },
            "required_directives": {
                "object-src": ["'none'"],
                "base-uri": ["'none'"],
            },
            "script_authorization": {
                "mode": "nonce_or_hash",
                "allowed_nonce_variables": ["$csp_nonce"],
                "allow_static_nonce": False,
                "allowed_hashes": [],
                "allow_host_allowlist_fallback": False,
                "require_strict_dynamic": False,
            },
            "forbidden_effective_capabilities": [
                "unsafe-eval",
                "generic-unsafe-inline",
            ],
            "frame_ancestors": {
                "mode": "deny",
            },
            "reporting": {
                "required": True,
                "modes": ["report-to", "report-uri"],
                "allowed_groups": ["csp"],
                "allowed_endpoint_origins": ["https://reports.example.test"],
            },
            "report_only": {
                "required": False,
            },
        },
        "headers": {
            "Referrer-Policy": {
                "required": True,
                "allowed_values": [
                    "no-referrer",
                    "strict-origin-when-cross-origin",
                ],
                "require_all_expected_statuses": True,
            },
            "X-Content-Type-Options": {
                "required": True,
                "allowed_values": ["nosniff"],
                "require_all_expected_statuses": True,
            },
            "Cross-Origin-Opener-Policy": {
                "required": True,
                "allowed_values": ["same-origin", "same-origin-allow-popups"],
                "require_all_expected_statuses": True,
            },
            "Strict-Transport-Security": {
                "required_on_schemes": ["https"],
                "min_max_age": 31536000,
                "include_subdomains": True,
                "require_all_expected_statuses": True,
            },
            "X-Frame-Options": {
                "mode": "transitional_optional",
            },
        },
    }


def api_response_profile() -> dict[str, object]:
    return {
        "conditional_branches": "require_all",
        "csp": {
            "enforcement": {
                "required": False,
            },
        },
        "headers": {
            "X-Content-Type-Options": {
                "required": True,
                "allowed_values": ["nosniff"],
                "require_all_expected_statuses": True,
            },
            "Referrer-Policy": {
                "required": True,
                "allowed_values": ["no-referrer"],
                "require_all_expected_statuses": True,
            },
        },
    }


def response_headers_policy_payload(
    *,
    routes: list[dict[str, object]],
    profiles: dict[str, dict[str, object]] | None = None,
    reporting_endpoints: dict[str, dict[str, object]] | None = None,
    unmatched_routes: str = "indeterminate",
    unresolved_internal_redirects: str = "indeterminate",
    requested_opt_in_tags: tuple[str, ...] = (),
) -> dict[str, object]:
    payload = base_policy_payload(requested_opt_in_tags=requested_opt_in_tags)
    payload["policy_id"] = "nginx-response-header-contract"
    payload["title"] = "Nginx response-header contract"
    payload["description"] = "Policy-backed response-header and CSP requirements for nginx."
    payload["nginx"] = {
        "response_headers": {
            "route_manifest": routes,
            "profiles": profiles
            if profiles is not None
            else {
                "browser-document": browser_document_profile(),
            },
            "reporting_endpoints": reporting_endpoints
            if reporting_endpoints is not None
            else {
                "csp": {
                    "allowed_urls": ["https://reports.example.test/csp"],
                }
            },
            "unmatched_routes": unmatched_routes,
            "unresolved_internal_redirects": unresolved_internal_redirects,
        }
    }
    return payload


def resolved_response_headers_policy(
    tmp_path: Path,
    payload: dict[str, object],
    *,
    target_name: str = "nginx.conf",
):
    return resolved_policy(tmp_path, payload, target_name=target_name)


__all__ = [
    "api_response_profile",
    "browser_document_profile",
    "resolved_response_headers_policy",
    "response_headers_policy_payload",
    "response_route",
]
