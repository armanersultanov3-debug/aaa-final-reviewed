from __future__ import annotations

from pathlib import Path

from tests.nginx_response_header_policy_helpers import (
    browser_document_profile,
    resolved_response_headers_policy,
    response_headers_policy_payload,
    response_route,
)
from webconf_audit.local.nginx import analyze_nginx_config


def _assessment_by_id(result, control_id: str):
    assessment = next(
        (
            candidate
            for candidate in result.control_assessments
            if candidate.control_id == control_id
        ),
        None,
    )
    if assessment is None:
        available_ids = sorted(
            candidate.control_id for candidate in result.control_assessments
        )
        raise AssertionError(
            f"Control assessment {control_id!r} not found. Available controls: {available_ids!r}"
        )
    return assessment


def _analyze_custom_profile(
    tmp_path: Path,
    *,
    profile: dict[str, object],
    add_headers: tuple[str, ...],
    configured_server_name: str = "www.example.test",
    route_server_name: str = "www.example.test",
):
    config_path = tmp_path / "nginx.conf"
    rendered_headers = "".join(
        f"            {directive}\n"
        for directive in add_headers
    )
    config_path.write_text(
        "http {\n"
        "    server {\n"
        f"        server_name {configured_server_name};\n"
        "        location / {\n"
        f"{rendered_headers}"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_response_headers_policy(
        tmp_path,
        response_headers_policy_payload(
            routes=[
                response_route(
                    route_id="custom-route",
                    server_names=(route_server_name,),
                    profile="custom-profile",
                    declared_location={"modifier": "prefix", "pattern": "/"},
                )
            ],
            profiles={"custom-profile": profile},
        ),
    )
    return analyze_nginx_config(str(config_path), policy=policy)


def test_response_header_policy_emits_csp_and_header_assessments(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        server_name www.example.test;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        location / {\n"
        "            add_header Content-Security-Policy \"object-src 'none'; base-uri 'none'; script-src 'nonce-$csp_nonce'; frame-ancestors 'none'; report-to csp\" always;\n"
        "            add_header Reporting-Endpoints 'csp=\"https://reports.example.test/csp\"' always;\n"
        "            add_header Referrer-Policy no-referrer always;\n"
        "            add_header X-Content-Type-Options nosniff always;\n"
        "            add_header Cross-Origin-Opener-Policy same-origin always;\n"
        "            add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_response_headers_policy(
        tmp_path,
        response_headers_policy_payload(
            routes=[
                response_route(
                    route_id="app-html",
                    server_names=("www.example.test",),
                    profile="browser-document",
                    declared_location={"modifier": "prefix", "pattern": "/"},
                    sample_uris=("/", "/account"),
                    expected_statuses=(200, 404, 500),
                )
            ]
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    assert _assessment_by_id(result, "cis-nginx-5.3.2.csp").status == "pass"
    assert _assessment_by_id(result, "cis-nginx-5.3.3.referrer-policy").status == "pass"
    assert _assessment_by_id(result, "asvs-5.0.0-v3.4.3.csp-quality").status == "pass"
    assert _assessment_by_id(result, "asvs-5.0.0-v3.4.6.frame-ancestors").status == "pass"
    assert _assessment_by_id(result, "asvs-5.0.0-v3.4.7.csp-reporting").status == "pass"
    assert _assessment_by_id(result, "asvs-5.0.0-v3.4.1.hsts").status == "pass"
    assert _assessment_by_id(result, "asvs-5.0.0-v3.4.4.x-content-type-options").status == "pass"
    assert _assessment_by_id(result, "asvs-5.0.0-v3.4.8.coop").status == "pass"


def test_response_header_policy_fails_when_only_report_only_csp_exists(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        server_name www.example.test;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        location / {\n"
        "            add_header Content-Security-Policy-Report-Only \"object-src 'none'; base-uri 'none'; script-src 'nonce-$csp_nonce'; frame-ancestors 'none'; report-to csp\" always;\n"
        "            add_header Reporting-Endpoints 'csp=\"https://reports.example.test/csp\"' always;\n"
        "            add_header Referrer-Policy no-referrer always;\n"
        "            add_header X-Content-Type-Options nosniff always;\n"
        "            add_header Cross-Origin-Opener-Policy same-origin always;\n"
        "            add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_response_headers_policy(
        tmp_path,
        response_headers_policy_payload(
            routes=[
                response_route(
                    route_id="app-html",
                    server_names=("www.example.test",),
                    profile="browser-document",
                    declared_location={"modifier": "prefix", "pattern": "/"},
                )
            ]
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    assert _assessment_by_id(result, "cis-nginx-5.3.2.csp").status == "fail"


def test_response_header_policy_suppresses_csp_value_review_for_explicit_scope(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        server_name www.example.test;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        location / {\n"
        "            add_header Content-Security-Policy \"object-src 'none'; base-uri 'none'; script-src 'nonce-$csp_nonce'; frame-ancestors 'none'; report-to csp\" always;\n"
        "            add_header Reporting-Endpoints 'csp=\"https://reports.example.test/csp\"' always;\n"
        "            add_header Referrer-Policy no-referrer always;\n"
        "            add_header X-Content-Type-Options nosniff always;\n"
        "            add_header Cross-Origin-Opener-Policy same-origin always;\n"
        "            add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_response_headers_policy(
        tmp_path,
        response_headers_policy_payload(
            routes=[
                response_route(
                    route_id="app-html",
                    server_names=("www.example.test",),
                    profile="browser-document",
                    declared_location={"modifier": "prefix", "pattern": "/"},
                )
            ],
            requested_opt_in_tags=("policy-review",),
        ),
    )

    result = analyze_nginx_config(
        str(config_path),
        enable_policy_review=True,
        policy=policy,
    )

    assert _assessment_by_id(result, "cis-nginx-5.3.2.csp").status == "pass"
    assert "nginx.csp_value_review" not in {finding.rule_id for finding in result.findings}


def test_response_header_policy_keeps_shared_csp_review_when_other_scopes_remain_unassessed(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        server_name www.example.test;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        add_header Content-Security-Policy \"object-src 'none'; base-uri 'none'; script-src 'nonce-$csp_nonce'; frame-ancestors 'none'; report-to csp\" always;\n"
        "        add_header Reporting-Endpoints 'csp=\"https://reports.example.test/csp\"' always;\n"
        "        add_header Referrer-Policy no-referrer always;\n"
        "        add_header X-Content-Type-Options nosniff always;\n"
        "        add_header Cross-Origin-Opener-Policy same-origin always;\n"
        "        add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "        location /selected/ {\n"
        "            return 200;\n"
        "        }\n"
        "        location /other/ {\n"
        "            return 200;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    policy = resolved_response_headers_policy(
        tmp_path,
        response_headers_policy_payload(
            routes=[
                response_route(
                    route_id="selected-html",
                    server_names=("www.example.test",),
                    profile="browser-document",
                    declared_location={"modifier": "prefix", "pattern": "/selected/"},
                    sample_uris=("/selected/",),
                )
            ],
            requested_opt_in_tags=("policy-review",),
        ),
    )

    result = analyze_nginx_config(
        str(config_path),
        enable_policy_review=True,
        policy=policy,
    )

    assert _assessment_by_id(result, "cis-nginx-5.3.2.csp").status == "pass"
    assert "nginx.csp_value_review" in {finding.rule_id for finding in result.findings}


def test_response_header_policy_marks_multiple_allowlist_policies_indeterminate(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        server_name www.example.test;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        location / {\n"
        "            add_header Content-Security-Policy \"object-src 'none'; base-uri 'none'; script-src 'self'; frame-ancestors 'none'; report-to csp\" always;\n"
        "            add_header Content-Security-Policy \"script-src https://cdn.example.test\" always;\n"
        "            add_header Reporting-Endpoints 'csp=\"https://reports.example.test/csp\"' always;\n"
        "            add_header Referrer-Policy no-referrer always;\n"
        "            add_header X-Content-Type-Options nosniff always;\n"
        "            add_header Cross-Origin-Opener-Policy same-origin always;\n"
        "            add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    allowlist_profile = browser_document_profile()
    allowlist_profile["csp"]["script_authorization"] = {
        "mode": "allowlist",
        "allowed_nonce_variables": [],
        "allow_static_nonce": False,
        "allowed_hashes": [],
        "allow_host_allowlist_fallback": True,
        "require_strict_dynamic": False,
    }
    policy = resolved_response_headers_policy(
        tmp_path,
        response_headers_policy_payload(
            routes=[
                response_route(
                    route_id="app-html",
                    server_names=("www.example.test",),
                    profile="browser-document",
                    declared_location={"modifier": "prefix", "pattern": "/"},
                )
            ],
            profiles={"browser-document": allowlist_profile},
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    assert _assessment_by_id(result, "asvs-5.0.0-v3.4.3.csp-quality").status == "indeterminate"


def test_response_header_policy_accepts_quoted_hash_sources_in_csp_and_policy(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        server_name www.example.test;\n"
        "        ssl_certificate cert.pem;\n"
        "        ssl_certificate_key cert.key;\n"
        "        location / {\n"
        "            add_header Content-Security-Policy \"object-src 'none'; base-uri 'none'; script-src 'sha256-QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE='; frame-ancestors 'none'; report-to csp\" always;\n"
        "            add_header Reporting-Endpoints 'csp=\"https://reports.example.test/csp\"' always;\n"
        "            add_header Referrer-Policy no-referrer always;\n"
        "            add_header X-Content-Type-Options nosniff always;\n"
        "            add_header Cross-Origin-Opener-Policy same-origin always;\n"
        "            add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
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
    policy = resolved_response_headers_policy(
        tmp_path,
        response_headers_policy_payload(
            routes=[
                response_route(
                    route_id="app-html",
                    server_names=("www.example.test",),
                    profile="browser-document",
                    declared_location={"modifier": "prefix", "pattern": "/"},
                )
            ],
            profiles={"browser-document": profile},
        ),
    )

    result = analyze_nginx_config(str(config_path), policy=policy)

    assert _assessment_by_id(result, "asvs-5.0.0-v3.4.3.csp-quality").status == "pass"


def test_response_header_policy_treats_required_directives_as_minimum_tokens(
    tmp_path: Path,
) -> None:
    result = _analyze_custom_profile(
        tmp_path,
        profile={
            "conditional_branches": "require_all",
            "csp": {
                "enforcement": {
                    "required": True,
                    "additional_policies": "allow",
                },
                "required_directives": {
                    "default-src": ["'self'"],
                },
            },
        },
        add_headers=(
            "add_header Content-Security-Policy \"default-src 'self' https:\" always;",
        ),
    )

    assert _assessment_by_id(result, "asvs-5.0.0-v3.4.3.csp-quality").status == "pass"


def test_response_header_policy_does_not_accept_unlisted_hash_for_nonce_only_strategy(
    tmp_path: Path,
) -> None:
    result = _analyze_custom_profile(
        tmp_path,
        profile={
            "conditional_branches": "require_all",
            "csp": {
                "enforcement": {
                    "required": True,
                    "additional_policies": "allow",
                },
                "script_authorization": {
                    "mode": "nonce_or_hash",
                    "allowed_nonce_variables": ["$csp_nonce"],
                    "allow_static_nonce": False,
                    "allowed_hashes": [],
                    "allow_host_allowlist_fallback": False,
                    "require_strict_dynamic": False,
                },
            },
        },
        add_headers=(
            "add_header Content-Security-Policy \"script-src 'sha256-QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE='\" always;",
        ),
    )

    assert _assessment_by_id(result, "asvs-5.0.0-v3.4.3.csp-quality").status == "fail"


def test_response_header_policy_treats_missing_script_restriction_as_unsafe(
    tmp_path: Path,
) -> None:
    result = _analyze_custom_profile(
        tmp_path,
        profile={
            "conditional_branches": "require_all",
            "csp": {
                "enforcement": {
                    "required": True,
                    "additional_policies": "allow",
                },
                "forbidden_effective_capabilities": ["unsafe-eval"],
            },
        },
        add_headers=(
            "add_header Content-Security-Policy \"object-src 'none'\" always;",
        ),
    )

    assessment = _assessment_by_id(result, "asvs-5.0.0-v3.4.3.csp-quality")
    assert assessment.status == "fail"
    assert any(
        failure.startswith("forbidden-capability:unsafe-eval:")
        for failure in assessment.metadata["failures"]
    )


def test_response_header_policy_require_parseable_marks_structural_error_indeterminate(
    tmp_path: Path,
) -> None:
    result = _analyze_custom_profile(
        tmp_path,
        profile={
            "conditional_branches": "require_all",
            "csp": {
                "enforcement": {
                    "required": True,
                    "additional_policies": "require_parseable",
                },
            },
        },
        add_headers=(
            "add_header Content-Security-Policy \"default-src 'self',\" always;",
        ),
    )

    assert _assessment_by_id(result, "cis-nginx-5.3.2.csp").status == "indeterminate"


def test_unmatched_response_header_route_emits_only_declared_component_controls(
    tmp_path: Path,
) -> None:
    result = _analyze_custom_profile(
        tmp_path,
        profile={
            "conditional_branches": "require_all",
            "headers": {
                "Referrer-Policy": {
                    "required": True,
                    "allowed_values": ["no-referrer"],
                },
            },
        },
        add_headers=(),
        configured_server_name="other.example.test",
    )

    assert {
        assessment.control_id
        for assessment in result.control_assessments
    } == {
        "cis-nginx-5.3.3.referrer-policy",
        "asvs-5.0.0-v3.4.5.referrer-policy",
        "policy.nginx.response-headers.custom-profile",
    }


def test_response_header_policy_evaluates_permissions_policy_and_x_frame_options(
    tmp_path: Path,
) -> None:
    result = _analyze_custom_profile(
        tmp_path,
        profile={
            "conditional_branches": "require_all",
            "headers": {
                "Permissions-Policy": {
                    "required": True,
                    "allowed_values": ["geolocation=(), camera=()"],
                    "require_all_expected_statuses": True,
                },
                "X-Frame-Options": {
                    "mode": "transitional_optional",
                },
            },
        },
        add_headers=(
            "add_header Permissions-Policy \"geolocation=(), camera=()\" always;",
            "add_header X-Frame-Options SAMEORIGIN always;",
        ),
    )

    assert _assessment_by_id(
        result,
        "policy.nginx.response-headers.custom-profile.permissions-policy",
    ).status == "pass"
    assert _assessment_by_id(
        result,
        "policy.nginx.response-headers.custom-profile.x-frame-options",
    ).status == "pass"
    assert _assessment_by_id(
        result,
        "policy.nginx.response-headers.custom-profile",
    ).status == "pass"
