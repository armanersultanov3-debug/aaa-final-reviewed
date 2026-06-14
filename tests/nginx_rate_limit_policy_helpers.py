from __future__ import annotations

from pathlib import Path

from tests.nginx_logging_policy_helpers import base_policy_payload, resolved_policy


def request_zone_inventory_entry(
    *,
    allowed_keys: tuple[str, ...] = ("$binary_remote_addr",),
    min_size: str = "10m",
    min_rate: str = "1r/s",
    max_rate: str = "20r/s",
) -> dict[str, object]:
    return {
        "allowed_keys": list(allowed_keys),
        "min_size": min_size,
        "rate": {
            "min": min_rate,
            "max": max_rate,
        },
    }


def connection_zone_inventory_entry(
    *,
    allowed_keys: tuple[str, ...] = ("$binary_remote_addr",),
    min_size: str = "10m",
) -> dict[str, object]:
    return {
        "allowed_keys": list(allowed_keys),
        "min_size": min_size,
    }


def public_api_rate_limit_profile(
    *,
    profile_id: str = "public-api",
    server_names: tuple[str, ...] = ("api.example.test",),
    declared_locations: tuple[dict[str, object], ...] = (),
    sample_uris: tuple[str, ...] = ("/v1/users",),
    request: dict[str, object] | None = None,
    connection: dict[str, object] | None = None,
) -> dict[str, object]:
    if request is None:
        request = {
            "required": True,
            "accepted_zones": ["api_per_ip"],
            "require_all_zones": False,
            "additional_zones": "allow",
            "burst": {"min": 0, "max": 20},
            "delay_mode": "default",
            "dry_run": False,
            "allowed_rejection_statuses": [429, 503],
            "allowed_log_levels": ["notice", "warn", "error"],
        }
    if connection is None:
        connection = {
            "required": True,
            "accepted_zones": ["api_conn_per_ip"],
            "require_all_zones": False,
            "additional_zones": "allow",
            "connections": {"min": 1, "max": 20},
            "dry_run": False,
            "allowed_rejection_statuses": [429, 503],
            "allowed_log_levels": ["notice", "warn", "error"],
        }

    applies_to: dict[str, object] = {"server_names": list(server_names)}
    if declared_locations:
        applies_to["declared_locations"] = list(declared_locations)
    if sample_uris:
        applies_to["sample_uris"] = list(sample_uris)

    payload: dict[str, object] = {
        "profile_id": profile_id,
        "applies_to": applies_to,
    }
    if request is not None:
        payload["request"] = request
    if connection is not None:
        payload["connection"] = connection
    return payload


def rate_limits_policy_payload(
    *,
    profiles: list[dict[str, object]],
    request_inventory: dict[str, dict[str, object]] | None = None,
    connection_inventory: dict[str, dict[str, object]] | None = None,
    unmatched_routes: str = "indeterminate",
    unresolved_internal_redirects: str = "indeterminate",
    requested_opt_in_tags: tuple[str, ...] = (),
) -> dict[str, object]:
    payload = base_policy_payload(requested_opt_in_tags=requested_opt_in_tags)
    payload["policy_id"] = "nginx-rate-limit-contract"
    payload["title"] = "Nginx rate-limit contract"
    payload["description"] = "Policy-backed request and connection limit requirements for nginx."
    payload["nginx"] = {
        "rate_limits": {
            "zone_inventory": {
                "request": request_inventory
                if request_inventory is not None
                else {
                    "api_per_ip": request_zone_inventory_entry(),
                },
                "connection": connection_inventory
                if connection_inventory is not None
                else {
                    "api_conn_per_ip": connection_zone_inventory_entry(),
                },
            },
            "profiles": profiles,
            "unmatched_routes": unmatched_routes,
            "unresolved_internal_redirects": unresolved_internal_redirects,
        }
    }
    return payload


def resolved_rate_limit_policy(
    tmp_path: Path,
    payload: dict[str, object],
    *,
    target_name: str = "nginx.conf",
):
    return resolved_policy(tmp_path, payload, target_name=target_name)


__all__ = [
    "connection_zone_inventory_entry",
    "public_api_rate_limit_profile",
    "rate_limits_policy_payload",
    "request_zone_inventory_entry",
    "resolved_rate_limit_policy",
]
