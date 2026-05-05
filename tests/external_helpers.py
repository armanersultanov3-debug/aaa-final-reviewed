import http.client
from datetime import timezone

import pytest

from webconf_audit.external.recon import ErrorPageProbe, MalformedRequestProbe, OptionsObservation, ProbeAttempt, ProbeTarget, SensitivePathProbe, ServerIdentification, ServerIdentificationEvidence, TLSInfo, analyze_external_target, _match_error_page_body, _match_malformed_response_body, _parse_malformed_response
from webconf_audit.external.rules._helpers import _parse_cert_date
from webconf_audit.external.rules import hostname_matches_san, run_external_rules


def _analyze_with_probe_attempts(
    monkeypatch,
    probe_attempts: list[ProbeAttempt],
    target: str = "example.com",
    sensitive_path_probes: list[SensitivePathProbe] | None = None,
    error_page_probes: list[ErrorPageProbe] | None = None,
    malformed_request_probes: list[MalformedRequestProbe] | None = None,
    additional_probe_attempts: list[ProbeAttempt] | None = None,
):
    extra_attempts = additional_probe_attempts or []
    attempts_by_target = {
        attempt.target: attempt
        for attempt in [*probe_attempts, *extra_attempts]
    }

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_probe_targets",
        lambda _external_target: [attempt.target for attempt in probe_attempts],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_target",
        lambda probe_target: attempts_by_target[probe_target],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        lambda successful_attempts, identification=None: (
            sensitive_path_probes if sensitive_path_probes is not None else []
        ),
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: error_page_probes if error_page_probes is not None else [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: malformed_request_probes if malformed_request_probes is not None else [],
    )

    return analyze_external_target(target)


_ALL_SECURITY_HEADERS = {
    "strict_transport_security_header": "max-age=31536000; includeSubDomains",
    "x_frame_options_header": "DENY",
    "x_content_type_options_header": "nosniff",
    "content_security_policy_header": (
        "default-src 'self'; frame-ancestors 'self'; object-src 'none'; "
        "base-uri 'none'; report-to csp-endpoint"
    ),
    "referrer_policy_header": "strict-origin-when-cross-origin",
    "permissions_policy_header": "geolocation=()",
    "cross_origin_embedder_policy_header": "require-corp",
    "cross_origin_opener_policy_header": "same-origin",
    "cross_origin_resource_policy_header": "same-origin",
}


def _server_identification(
    server_type: str | None,
    confidence: str,
    *,
    evidence: tuple[ServerIdentificationEvidence, ...] = (),
) -> ServerIdentification:
    return ServerIdentification(
        server_type=server_type,
        confidence=confidence,
        evidence=evidence,
        candidate_server_types=(server_type,) if server_type is not None else (),
    )

def _https_probe_with_headers(**overrides) -> ProbeAttempt:
    defaults = {
        "target": ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
        "tcp_open": True,
        "status_code": 200,
        "reason_phrase": "OK",
        "server_header": "nginx",
        **_ALL_SECURITY_HEADERS,
    }
    defaults.update(overrides)
    return ProbeAttempt(**defaults)


def _http_probe_with_headers(**overrides) -> ProbeAttempt:
    defaults = {
        "target": ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
        "tcp_open": True,
        "status_code": 200,
        "reason_phrase": "OK",
        "server_header": "nginx",
        **_ALL_SECURITY_HEADERS,
    }
    defaults.update(overrides)
    return ProbeAttempt(**defaults)


def _http_redirect_probe(
    *,
    target: ProbeTarget | None = None,
    status_code: int = 301,
    reason_phrase: str = "Moved Permanently",
    server_header: str = "nginx",
    location_header: str = "https://example.com/",
) -> ProbeAttempt:
    return ProbeAttempt(
        target=target or ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
        tcp_open=True,
        status_code=status_code,
        reason_phrase=reason_phrase,
        server_header=server_header,
        location_header=location_header,
    )


def _sensitive_path_probe(
    path: str,
    *,
    status_code: int = 200,
    content_type: str | None = "text/html",
    body_snippet: str | None = None,
) -> SensitivePathProbe:
    return SensitivePathProbe(
        url=f"https://example.com{path}",
        path=path,
        status_code=status_code,
        content_type=content_type,
        body_snippet=body_snippet,
    )

def _setup_head_fallback_probe(monkeypatch, head_status, head_error=None):
    """Set up monkeypatches where HEAD returns the given status/error and GET returns 200."""
    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")
    methods_called = []

    def fake_try(probe_target, method):
        methods_called.append(method)
        if method == "HEAD":
            if head_error:
                return ProbeAttempt(
                    target=probe_target,
                    tcp_open=True,
                    error_message=head_error,
                )
            return ProbeAttempt(
                target=probe_target,
                tcp_open=True,
                effective_method="HEAD",
                status_code=head_status,
                reason_phrase="Method Not Allowed" if head_status == 405 else "Not Implemented",
                server_header="nginx",
            )
        return ProbeAttempt(
            target=probe_target,
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            content_type_header="text/html",
            **_ALL_SECURITY_HEADERS,
        )

    monkeypatch.setattr("webconf_audit.external.recon._is_tcp_port_open", lambda h, p: True)
    monkeypatch.setattr("webconf_audit.external.recon._try_http_method", fake_try)

    return target, methods_called

_VALID_TLS = TLSInfo(
    protocol_version="TLSv1.3",
    cert_not_before="Jan  1 00:00:00 2025 GMT",
    cert_not_after="Dec 31 23:59:59 2027 GMT",
    cert_subject="commonName=example.com",
    cert_issuer="commonName=Test CA",
)


__all__ = [
    "ErrorPageProbe",
    "MalformedRequestProbe",
    "OptionsObservation",
    "ProbeAttempt",
    "ProbeTarget",
    "SensitivePathProbe",
    "ServerIdentification",
    "ServerIdentificationEvidence",
    "TLSInfo",
    "analyze_external_target",
    "hostname_matches_san",
    "http",
    "pytest",
    "run_external_rules",
    "timezone",
    "_ALL_SECURITY_HEADERS",
    "_VALID_TLS",
    "_analyze_with_probe_attempts",
    "_http_probe_with_headers",
    "_http_redirect_probe",
    "_https_probe_with_headers",
    "_match_error_page_body",
    "_match_malformed_response_body",
    "_parse_cert_date",
    "_parse_malformed_response",
    "_sensitive_path_probe",
    "_server_identification",
    "_setup_head_fallback_probe",
]
