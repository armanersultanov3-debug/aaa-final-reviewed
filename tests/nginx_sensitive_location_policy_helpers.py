from __future__ import annotations

from pathlib import Path

from tests.nginx_logging_policy_helpers import base_policy_payload, resolved_policy, write_policy


def sensitive_location_entry(
    *,
    entry_id: str = "admin-console",
    kind: str = "admin",
    server_names: tuple[str, ...] = ("example.test",),
    declared_location: dict[str, object] | None = None,
    sample_uris: tuple[str, ...] = ("/admin/",),
    exposure: str = "external",
    required_controls: dict[str, object] | None = None,
) -> dict[str, object]:
    if declared_location is None:
        declared_location = {
            "modifier": "prefix_no_regex",
            "pattern": "/admin/",
        }
    if required_controls is None:
        required_controls = {
            "all_of": [
                {
                    "ip_allowlist": {
                        "allowed_cidrs": ["10.20.0.0/16"],
                        "require_deny_all_fallback": True,
                    }
                },
                {"auth_request": {}},
            ],
            "satisfy": "all",
        }
    return {
        "entry_id": entry_id,
        "kind": kind,
        "server_names": list(server_names),
        "declared_location": declared_location,
        "sample_uris": list(sample_uris),
        "exposure": exposure,
        "required_controls": required_controls,
    }


def sensitive_locations_policy_payload(
    *,
    catalog: list[dict[str, object]],
    unmatched_entries: str = "indeterminate",
    allow_unresolved_internal_redirects: bool = False,
    requested_opt_in_tags: tuple[str, ...] = (),
) -> dict[str, object]:
    payload = base_policy_payload(requested_opt_in_tags=requested_opt_in_tags)
    payload["policy_id"] = "nginx-sensitive-location-contract"
    payload["title"] = "Nginx sensitive location contract"
    payload["description"] = "Policy-backed access control requirements for sensitive nginx routes."
    payload["nginx"] = {
        "sensitive_locations": {
            "catalog": catalog,
            "unmatched_entries": unmatched_entries,
            "allow_unresolved_internal_redirects": allow_unresolved_internal_redirects,
        }
    }
    return payload


def resolved_sensitive_location_policy(
    tmp_path: Path,
    payload: dict[str, object],
    *,
    target_name: str = "nginx.conf",
):
    return resolved_policy(
        tmp_path,
        payload,
        target_name=target_name,
    )


__all__ = [
    "resolved_sensitive_location_policy",
    "sensitive_location_entry",
    "sensitive_locations_policy_payload",
    "write_policy",
]
