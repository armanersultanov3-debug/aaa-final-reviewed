from tests.external_helpers import (
    ProbeAttempt,
    ProbeTarget,
    TLSInfo,
    _ALL_SECURITY_HEADERS,
    _analyze_with_probe_attempts,
)

def test_server_identification_nginx_with_strong_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    assert ident["confidence"] == "high"
    assert ident["ambiguous"] is False
    assert ident["candidate_server_types"] == ["nginx"]
    assert ident["evidence"][0]["source_url"] == "https://example.com/"
    assert ident["evidence"][0]["signal"] == "server_header"
    assert ident["evidence"][0]["indicates"] == "nginx"
    assert ident["evidence"][0]["strength"] == "strong"
    assert "probable_server_type: nginx" in result.diagnostics
    assert "identification_confidence: high" in result.diagnostics


def test_server_identification_apache_via_server_header(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58 (Ubuntu)",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "apache"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "apache"
    assert ident["confidence"] == "high"
    assert ident["ambiguous"] is False
    assert ident["candidate_server_types"] == ["apache"]
    assert ident["evidence"][0]["source_url"] == "https://example.com/"


def test_server_identification_iis_via_aspnet_headers(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_powered_by_header="ASP.NET",
            x_aspnet_version_header="4.0.30319",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "iis"
    assert ident["confidence"] == "medium"
    assert ident["ambiguous"] is False
    assert ident["candidate_server_types"] == ["iis"]
    assert len(ident["evidence"]) == 2
    assert {e["signal"] for e in ident["evidence"]} == {
        "x_powered_by_header",
        "x_aspnet_version_header",
    }
    assert {e["source_url"] for e in ident["evidence"]} == {"https://example.com/"}


def test_server_identification_unknown_with_no_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="custom-edge",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type is None
    ident = result.metadata["server_identification"]
    assert ident["server_type"] is None
    assert ident["confidence"] == "none"
    assert ident["evidence"] == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "external_server_type_unknown"


def test_server_identification_openresty_maps_to_nginx(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="openresty/1.21.4.1",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    assert ident["confidence"] == "high"
    assert ident["ambiguous"] is False


def test_server_identification_php_only_does_not_classify_apache(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_powered_by_header="PHP/8.2.0",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type is None
    ident = result.metadata["server_identification"]
    assert ident["server_type"] is None
    assert ident["confidence"] == "none"
    assert ident["ambiguous"] is False
    assert ident["candidate_server_types"] == []
    assert len(ident["evidence"]) == 1
    assert ident["evidence"][0]["source_url"] == "https://example.com/"
    assert ident["evidence"][0]["signal"] == "x_powered_by_header"
    assert ident["evidence"][0]["indicates"] is None
    assert ident["evidence"][0]["strength"] == "weak"
    assert len(result.issues) == 1
    assert result.issues[0].code == "external_server_type_unknown"


def test_server_identification_conflicting_https_and_http_evidence_is_ambiguous(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type is None
    ident = result.metadata["server_identification"]
    assert ident["server_type"] is None
    assert ident["confidence"] == "none"
    assert ident["ambiguous"] is True
    assert set(ident["candidate_server_types"]) == {"apache", "nginx"}
    assert {e["source_url"] for e in ident["evidence"]} == {
        "https://example.com/",
        "http://example.com/",
    }
    assert "identification_ambiguous: apache, nginx" in result.diagnostics
    assert len(result.issues) == 1
    assert result.issues[0].code == "external_server_type_ambiguous"


def test_server_identification_preserves_frontend_server_header_with_aspnet_headers(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58",
            x_powered_by_header="ASP.NET",
            x_aspnet_version_header="4.0.30319",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "apache"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "apache"
    assert ident["confidence"] == "high"
    assert ident["ambiguous"] is False
    assert ident["candidate_server_types"] == ["apache"]
    assert {e["source_url"] for e in ident["evidence"]} == {"https://example.com/"}
    assert {e["signal"] for e in ident["evidence"]} == {
        "server_header",
        "x_powered_by_header",
        "x_aspnet_version_header",
    }
    assert "probable_server_type: apache" in result.diagnostics
    assert "identification_confidence: high" in result.diagnostics
    assert result.issues == []


def test_server_identification_not_present_when_no_service(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=False,
            error_message="TCP connection failed.",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.server_type is None
    assert "server_identification" not in result.metadata


# ---------------------------------------------------------------------------
# HSTS max-age too short
# ---------------------------------------------------------------------------


def test_hsts_max_age_too_short_fires_for_low_value(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=3600",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_max_age_too_short" in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.hsts_max_age_too_short")
    assert "3600" in finding.description
    assert finding.location.details is not None
    assert "max-age=3600" in finding.location.details


def test_hsts_max_age_not_short_when_one_year(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_max_age_too_short" not in rule_ids


def test_hsts_max_age_not_short_when_header_missing(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_max_age_too_short" not in rule_ids


# ---------------------------------------------------------------------------
# CSP unsafe-inline / unsafe-eval
# ---------------------------------------------------------------------------


def test_csp_unsafe_inline_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'; script-src 'unsafe-inline'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.content_security_policy_unsafe_inline")
    assert "'unsafe-inline'" in finding.description
    assert finding.location.details is not None
    assert "Content-Security-Policy:" in finding.location.details


def test_csp_unsafe_eval_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'; script-src 'unsafe-eval'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_eval" in rule_ids


def test_csp_unsafe_inline_and_eval_both_fire(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="script-src 'unsafe-inline' 'unsafe-eval'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" in rule_ids
    assert "external.content_security_policy_unsafe_eval" in rule_ids


def test_csp_safe_policy_does_not_fire_unsafe_rules(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" not in rule_ids
    assert "external.content_security_policy_unsafe_eval" not in rule_ids


def test_csp_missing_does_not_fire_unsafe_rules(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" not in rule_ids
    assert "external.content_security_policy_unsafe_eval" not in rule_ids


# ---------------------------------------------------------------------------
# TLS certificate self-signed
# ---------------------------------------------------------------------------


def test_tls_self_signed_certificate_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            tls_info=TLSInfo(
                protocol_version="TLSv1.3",
                cert_subject="CN=example.com",
                cert_issuer="CN=example.com",
                cert_not_after="Dec 31 23:59:59 2027 GMT",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.tls_certificate_self_signed" in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.tls_certificate_self_signed")
    assert finding.location.kind == "tls"
    assert finding.location.details is not None
    assert "CN=example.com" in finding.location.details


def test_tls_ca_signed_certificate_does_not_fire(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            tls_info=TLSInfo(
                protocol_version="TLSv1.3",
                cert_subject="CN=example.com",
                cert_issuer="CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US",
                cert_not_after="Dec 31 23:59:59 2027 GMT",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.tls_certificate_self_signed" not in rule_ids


def test_tls_self_signed_not_fired_when_no_tls_info(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.tls_certificate_self_signed" not in rule_ids


# ---------------------------------------------------------------------------
# Regression: malformed HSTS numeric-prefix
# ---------------------------------------------------------------------------


def test_hsts_malformed_numeric_prefix_does_not_fire_too_short(monkeypatch) -> None:
    """max-age=3600abc is malformed, not 'too short'."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=3600abc",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    # Malformed value should NOT trigger the too-short rule.
    assert "external.hsts_max_age_too_short" not in rule_ids
    # Malformed value SHOULD trigger the invalid-header rule.
    assert "external.hsts_header_invalid" in rule_ids


# ---------------------------------------------------------------------------
# Regression: CSP mixed-scheme intent
# ---------------------------------------------------------------------------


def test_csp_unsafe_inline_on_http_only_does_not_fire(monkeypatch) -> None:
    """CSP unsafe rules are HTTPS-only; HTTP-only unsafe CSP is not flagged."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            content_security_policy_header="script-src 'unsafe-inline' 'unsafe-eval'",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" not in rule_ids
    assert "external.content_security_policy_unsafe_eval" not in rule_ids


def test_csp_mixed_scheme_only_https_unsafe_fires(monkeypatch) -> None:
    """HTTPS with unsafe CSP fires; HTTP on the same target does not drive CSP findings."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="script-src 'unsafe-inline' 'unsafe-eval'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            content_security_policy_header="default-src 'self'",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" in rule_ids
    assert "external.content_security_policy_unsafe_eval" in rule_ids
    unsafe_findings = [
        f for f in result.findings
        if f.rule_id
        in {
            "external.content_security_policy_unsafe_inline",
            "external.content_security_policy_unsafe_eval",
        }
    ]
    assert {f.location.target for f in unsafe_findings} == {"https://example.com/"}


# ---------------------------------------------------------------------------
# Regression: new findings coexist with server_identification metadata
# ---------------------------------------------------------------------------


def test_new_external_findings_coexist_with_server_identification(monkeypatch) -> None:
    """New external findings do not break or erase server_identification."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            strict_transport_security_header="max-age=3600",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'; script-src 'unsafe-inline'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
            tls_info=TLSInfo(
                protocol_version="TLSv1.3",
                cert_subject="CN=example.com",
                cert_issuer="CN=example.com",
                cert_not_after="Dec 31 23:59:59 2027 GMT",
            ),
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    # Server identification is present and correct.
    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    assert ident["confidence"] == "high"
    assert "probable_server_type: nginx" in result.diagnostics
    assert "identification_confidence: high" in result.diagnostics

    # New findings fire alongside identification.
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_max_age_too_short" in rule_ids
    assert "external.content_security_policy_unsafe_inline" in rule_ids
    assert "external.tls_certificate_self_signed" in rule_ids

    # Probe metadata is also preserved.
    assert "probe_attempts" in result.metadata
    assert len(result.metadata["probe_attempts"]) == 1


# ---------------------------------------------------------------------------
# HSTS missing includeSubDomains
# ---------------------------------------------------------------------------


def test_hsts_missing_include_subdomains_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.hsts_missing_include_subdomains")
    assert finding.location.details is not None
    assert "max-age=31536000" in finding.location.details


def test_hsts_with_include_subdomains_does_not_fire(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000; includeSubDomains",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" not in rule_ids


def test_hsts_include_subdomains_not_fired_when_hsts_invalid(monkeypatch) -> None:
    """Don't fire includeSubDomains rule when HSTS itself is invalid."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=3600abc",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" not in rule_ids


def test_hsts_include_subdomains_not_fired_when_hsts_missing(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" not in rule_ids


# ---------------------------------------------------------------------------
# HTTP redirect not permanent
# ---------------------------------------------------------------------------


def test_http_redirect_302_fires_not_permanent(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=302,
            reason_phrase="Found",
            server_header="nginx",
            location_header="https://example.com/",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.http_redirect_not_permanent" in rule_ids
    # Should NOT also fire http_not_redirected_to_https — it is redirecting.
    assert "external.http_not_redirected_to_https" not in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.http_redirect_not_permanent")
    assert "302" in finding.description
    assert finding.location.details is not None
    assert "302" in finding.location.details


def test_http_redirect_301_does_not_fire_not_permanent(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=301,
            reason_phrase="Moved Permanently",
            server_header="nginx",
            location_header="https://example.com/",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.http_redirect_not_permanent" not in rule_ids


def test_http_redirect_308_does_not_fire_not_permanent(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=308,
            reason_phrase="Permanent Redirect",
            server_header="nginx",
            location_header="https://example.com/",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.http_redirect_not_permanent" not in rule_ids


def test_http_no_redirect_does_not_fire_not_permanent(monkeypatch) -> None:
    """Non-redirecting HTTP does not trigger the redirect-permanence rule."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.http_redirect_not_permanent" not in rule_ids


# ---------------------------------------------------------------------------
# Cookie SameSite=None without Secure
# ---------------------------------------------------------------------------


def test_cookie_samesite_none_without_secure_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc123; SameSite=None",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cookie_samesite_none_without_secure" in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.cookie_samesite_none_without_secure")
    assert "session_id" in finding.description


def test_cookie_samesite_none_with_secure_does_not_fire(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc123; SameSite=None; Secure",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cookie_samesite_none_without_secure" not in rule_ids


def test_cookie_samesite_lax_without_secure_does_not_fire(monkeypatch) -> None:
    """Only SameSite=None triggers this rule, not Lax or Strict."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc123; SameSite=Lax",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cookie_samesite_none_without_secure" not in rule_ids


def test_cookie_samesite_none_on_non_session_cookie_does_not_fire(monkeypatch) -> None:
    """Non-session cookies are not checked."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("theme=dark; SameSite=None",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cookie_samesite_none_without_secure" not in rule_ids


def test_cookie_samesite_none_mixed_scheme_only_fires_once(monkeypatch) -> None:
    """SameSite=None without Secure fires on the endpoint that set the cookie."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc; SameSite=None; Secure",),
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc; SameSite=None",),
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    samesite_findings = [
        f for f in result.findings
        if f.rule_id == "external.cookie_samesite_none_without_secure"
    ]
    # Only the HTTP endpoint's cookie should fire (HTTPS one has Secure).
    assert len(samesite_findings) == 1
    assert "http://example.com/" in samesite_findings[0].location.target


# ---------------------------------------------------------------------------
# Regression: 307 temporary redirect must fire not-permanent
# ---------------------------------------------------------------------------


def test_http_redirect_307_fires_not_permanent(monkeypatch) -> None:
    """307 Temporary Redirect to HTTPS must trigger the not-permanent rule."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=307,
            reason_phrase="Temporary Redirect",
            server_header="nginx",
            location_header="https://example.com/",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.http_redirect_not_permanent" in rule_ids
    assert "external.http_not_redirected_to_https" not in rule_ids


# ---------------------------------------------------------------------------
# Regression: malformed includeSubDomains must not count as present
# ---------------------------------------------------------------------------


def test_hsts_malformed_include_subdomains_fires(monkeypatch) -> None:
    """includeSubDomains=false is malformed and must not suppress the rule."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000; includeSubDomains=false",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" in rule_ids


# ---------------------------------------------------------------------------
# Regression: second-batch rules coexist with server_identification
# ---------------------------------------------------------------------------


def test_second_batch_rules_coexist_with_server_identification(monkeypatch) -> None:
    """New rules fire alongside traceable server identification metadata."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
            set_cookie_headers=("session_id=abc; SameSite=None",),
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=302,
            reason_phrase="Found",
            server_header="nginx/1.24.0",
            location_header="https://example.com/",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    # Server identification is present and correct.
    assert result.server_type == "nginx"
