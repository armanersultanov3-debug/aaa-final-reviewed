from tests.external_helpers import (
    OptionsObservation,
    ProbeAttempt,
    ProbeTarget,
    TLSInfo,
    analyze_external_target,
    hostname_matches_san,
    timezone,
    _ALL_SECURITY_HEADERS,
    _VALID_TLS,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    _parse_cert_date,
)

def test_tls_info_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(tls_info=_VALID_TLS),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta is not None
    assert tls_meta["protocol_version"] == "TLSv1.3"
    assert tls_meta["cert_not_after"] == "Dec 31 23:59:59 2027 GMT"
    assert tls_meta["cert_subject"] == "commonName=example.com"
    assert tls_meta["cert_issuer"] == "commonName=Test CA"


def test_tls_info_none_when_http(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["tls_info"] is None


def test_tls_cipher_info_in_metadata(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        cipher_protocol="TLSv1.3",
        cert_not_before="Jan  1 00:00:00 2025 GMT",
        cert_not_after="Dec 31 23:59:59 2027 GMT",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Test CA",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["cipher_name"] == "TLS_AES_256_GCM_SHA384"
    assert tls_meta["cipher_bits"] == 256
    assert tls_meta["cipher_protocol"] == "TLSv1.3"


def test_tls_cipher_none_when_not_available(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2")
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["cipher_name"] is None
    assert tls_meta["cipher_bits"] is None
    assert tls_meta["cipher_protocol"] is None


def test_tls_san_in_metadata(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_san=("example.com", "*.example.com", "www.example.com"),
        cert_not_before="Jan  1 00:00:00 2025 GMT",
        cert_not_after="Dec 31 23:59:59 2027 GMT",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Test CA",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["cert_san"] == ["example.com", "*.example.com", "www.example.com"]


def test_tls_san_empty_when_absent(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3")
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["cert_san"] == []






def test_tls_cipher_in_diagnostics(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert any("tls_cipher: TLS_AES_256_GCM_SHA384 (256 bits)" in d for d in result.diagnostics)


def test_tls_san_in_diagnostics(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_san=("example.com", "www.example.com"),
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert any("cert_san: example.com, www.example.com" in d for d in result.diagnostics)


def test_deep_tls_probe_results_in_diagnostics(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        supported_protocols=("TLSv1.2", "TLSv1.3"),
        cert_chain_complete=False,
        cert_chain_error="unable to get local issuer certificate",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert any("tls_supported: TLSv1.2, TLSv1.3" in d for d in result.diagnostics)
    assert any("cert_chain_complete: False" in d for d in result.diagnostics)
    assert any(
        "cert_chain_error: unable to get local issuer certificate" in d
        for d in result.diagnostics
    )


# --- _extract_san unit test ---


def test_extract_san_helper() -> None:
    from webconf_audit.external.recon import _extract_san

    cert = {"subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com"))}
    assert _extract_san(cert) == ("example.com", "*.example.com")


def test_extract_san_empty_when_no_san() -> None:
    from webconf_audit.external.recon import _extract_san

    assert _extract_san({}) == ()
    assert _extract_san({"subjectAltName": None}) == ()
    assert _extract_san({"subjectAltName": ()}) == ()


def test_extract_san_filters_non_dns_entries() -> None:
    """Only DNS-type SAN entries are extracted; IP, email, URI are dropped."""
    from webconf_audit.external.recon import _extract_san

    cert = {
        "subjectAltName": (
            ("DNS", "example.com"),
            ("IP Address", "192.168.1.1"),
            ("DNS", "www.example.com"),
            ("email", "admin@example.com"),
            ("URI", "https://example.com"),
        ),
    }
    assert _extract_san(cert) == ("example.com", "www.example.com")


def test_extract_san_all_non_dns_returns_empty() -> None:
    """When all SAN entries are non-DNS, return empty tuple."""
    from webconf_audit.external.recon import _extract_san

    cert = {
        "subjectAltName": (
            ("IP Address", "10.0.0.1"),
            ("email", "admin@example.com"),
        ),
    }
    assert _extract_san(cert) == ()


# --- Certificate expired rule ---


def test_certificate_expired_fires(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cert_not_after="Jan  1 00:00:00 2020 GMT",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.certificate_expired" in {f.rule_id for f in result.findings}


def test_certificate_expired_does_not_fire_for_valid_cert(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cert_not_after="Dec 31 23:59:59 2027 GMT",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.certificate_expired" not in {f.rule_id for f in result.findings}


def test_certificate_expired_does_not_fire_when_tls_info_absent(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.certificate_expired" not in {f.rule_id for f in result.findings}


# --- Certificate expires soon rule ---


def test_certificate_expires_soon_fires(monkeypatch) -> None:
    from datetime import datetime, timedelta, timezone

    soon = datetime.now(timezone.utc) + timedelta(days=10)
    cert_date = soon.strftime("%b %d %H:%M:%S %Y GMT")
    tls = TLSInfo(protocol_version="TLSv1.2", cert_not_after=cert_date)
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.certificate_expires_soon" in {f.rule_id for f in result.findings}


def test_certificate_expires_soon_does_not_fire_for_distant_expiry(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cert_not_after="Dec 31 23:59:59 2027 GMT",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.certificate_expires_soon" not in {f.rule_id for f in result.findings}


def test_certificate_expires_soon_does_not_fire_for_already_expired(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cert_not_after="Jan  1 00:00:00 2020 GMT",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.certificate_expired" in rule_ids
    assert "external.certificate_expires_soon" not in rule_ids


# ---------------------------------------------------------------------------
# OPTIONS observation – metadata
# ---------------------------------------------------------------------------


def test_options_observation_captured_in_metadata(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, OPTIONS")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    meta_obs = result.metadata["probe_attempts"][0]["options_observation"]
    assert meta_obs is not None
    assert meta_obs["status_code"] == 200
    assert meta_obs["allow_header"] == "GET, HEAD, OPTIONS"
    assert meta_obs["public_header"] is None
    assert meta_obs["error_message"] is None


def test_options_observation_none_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["options_observation"] is None


# ---------------------------------------------------------------------------
# external.options_method_exposed
# ---------------------------------------------------------------------------


def test_options_method_exposed_fires_when_allow_present(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, OPTIONS")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.options_method_exposed" in {f.rule_id for f in result.findings}


def test_options_method_exposed_fires_when_public_present(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, public_header="GET, HEAD, TRACE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.options_method_exposed" in {f.rule_id for f in result.findings}


def test_options_method_exposed_does_not_fire_without_observation(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.options_method_exposed" not in {f.rule_id for f in result.findings}


def test_options_method_exposed_does_not_fire_when_no_methods(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200)
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.options_method_exposed" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# external.dangerous_http_methods_enabled
# ---------------------------------------------------------------------------


def test_dangerous_methods_fires_for_trace_and_delete(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, TRACE, DELETE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.dangerous_http_methods_enabled" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "external.dangerous_http_methods_enabled"][0]
    assert "DELETE" in finding.description
    assert "TRACE" in finding.description


def test_dangerous_methods_fires_for_put_delete_only(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, PUT, DELETE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" in {f.rule_id for f in result.findings}


def test_dangerous_methods_does_not_fire_for_safe_methods(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, OPTIONS, POST")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" not in {f.rule_id for f in result.findings}


def test_dangerous_methods_case_insensitive(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="get, head, Trace, delete")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" in {f.rule_id for f in result.findings}


def test_dangerous_methods_whitespace_tolerant(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header=" GET , TRACE , DELETE ")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" in {f.rule_id for f in result.findings}


def test_dangerous_methods_does_not_fire_without_observation(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" not in {f.rule_id for f in result.findings}


def test_dangerous_methods_via_public_header(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, public_header="GET, HEAD, TRACE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# external.trace_method_exposed_via_options
# ---------------------------------------------------------------------------


def test_trace_via_options_fires_when_not_in_head_allow(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, TRACE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_exposed_via_options" in {f.rule_id for f in result.findings}


def test_trace_via_options_suppressed_when_already_in_head_allow(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, TRACE")
    probe_attempts = [
        _https_probe_with_headers(
            allow_header="GET, HEAD, TRACE",
            options_observation=obs,
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.trace_method_exposed_via_options" not in rule_ids
    assert "external.trace_method_allowed" in rule_ids


def test_trace_via_options_does_not_fire_without_observation(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_exposed_via_options" not in {f.rule_id for f in result.findings}


def test_trace_via_options_does_not_fire_when_no_trace(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, OPTIONS")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_exposed_via_options" not in {f.rule_id for f in result.findings}


def test_trace_via_options_public_header_sets_correct_source_detail(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, public_header="GET, HEAD, TRACE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    findings = [f for f in result.findings if f.rule_id == "external.trace_method_exposed_via_options"]
    assert len(findings) == 1
    assert findings[0].location.details == "OPTIONS Public"


# ---------------------------------------------------------------------------
# No false positives from new OPTIONS rules on baseline probes
# ---------------------------------------------------------------------------


def test_no_options_findings_on_baseline_probe(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    options_rule_ids = {
        "external.options_method_exposed",
        "external.dangerous_http_methods_enabled",
        "external.trace_method_exposed_via_options",
    }
    fired = options_rule_ids & {f.rule_id for f in result.findings}
    assert fired == set()


# ---------------------------------------------------------------------------
# Sensitive path probes – metadata
# ---------------------------------------------------------------------------

def test_allow_header_dangerous_methods_fires_for_put_delete(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, PUT, DELETE",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" in rule_ids
    finding = next(
        f for f in result.findings
        if f.rule_id == "external.allow_header_dangerous_methods"
    )
    assert "PUT" in finding.description
    assert "DELETE" in finding.description
    assert finding.location.details is not None
    assert "Allow:" in finding.location.details


def test_allow_header_dangerous_methods_does_not_fire_for_safe_methods(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, POST, OPTIONS",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" not in rule_ids


def test_allow_header_dangerous_methods_does_not_fire_for_trace_only(monkeypatch) -> None:
    """TRACE in Allow is covered by trace_method_allowed, not this rule."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, TRACE",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" not in rule_ids
    assert "external.trace_method_allowed" in rule_ids


def test_allow_header_dangerous_methods_case_insensitive(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="get, head, put, connect",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" in rule_ids


def test_allow_header_dangerous_methods_absent_allow_header(monkeypatch) -> None:
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
    assert "external.allow_header_dangerous_methods" not in rule_ids


# ---------------------------------------------------------------------------
# WebDAV methods exposed
# ---------------------------------------------------------------------------


def test_webdav_methods_in_allow_header_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, PROPFIND, MKCOL",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" in rule_ids
    finding = next(
        f for f in result.findings
        if f.rule_id == "external.webdav_methods_exposed"
    )
    assert "PROPFIND" in finding.description
    assert "MKCOL" in finding.description
    assert "Allow" in finding.description


def test_webdav_methods_in_options_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            options_observation=OptionsObservation(
                status_code=200,
                allow_header="GET, HEAD, PROPFIND, COPY, MOVE",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" in rule_ids
    finding = next(
        f for f in result.findings
        if f.rule_id == "external.webdav_methods_exposed"
    )
    assert "PROPFIND" in finding.description


def test_webdav_methods_not_fired_for_standard_methods(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, POST, OPTIONS",
            options_observation=OptionsObservation(
                status_code=200,
                allow_header="GET, HEAD, POST, OPTIONS",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" not in rule_ids


def test_webdav_methods_absent_observations(monkeypatch) -> None:
    """No Allow header and no OPTIONS -> no WebDAV finding."""
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
    assert "external.webdav_methods_exposed" not in rule_ids


def test_webdav_methods_case_insensitive(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="get, head, propfind, lock, unlock",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" in rule_ids


def test_method_rules_coexist_with_identification(monkeypatch) -> None:
    """Method-exposure rules fire alongside traceable server identification."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Microsoft-IIS/10.0",
            allow_header="GET, HEAD, PUT, DELETE, PROPFIND, LOCK",
            options_observation=OptionsObservation(
                status_code=200,
                allow_header="GET, HEAD, PUT, DELETE, TRACE, PROPFIND, LOCK",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    # Server identification works.
    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "iis"

    # Method rules fire.
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" in rule_ids
    assert "external.webdav_methods_exposed" in rule_ids
    assert "external.dangerous_http_methods_enabled" in rule_ids


# ---------------------------------------------------------------------------
# WebDAV via OPTIONS Public regression
# ---------------------------------------------------------------------------


def test_webdav_methods_via_options_public_fires(monkeypatch) -> None:
    """WebDAV methods exposed only through OPTIONS Public header."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Microsoft-IIS/10.0",
            options_observation=OptionsObservation(
                status_code=200,
                public_header="GET, HEAD, PROPFIND, LOCK, UNLOCK",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" in rule_ids
    finding = next(
        f for f in result.findings
        if f.rule_id == "external.webdav_methods_exposed"
    )
    assert "PROPFIND" in finding.description
    assert "OPTIONS Public" in finding.description
    assert "OPTIONS Public" in finding.location.details


# ---------------------------------------------------------------------------
# Mixed HTTP/HTTPS method exposure regression
# ---------------------------------------------------------------------------


def test_mixed_scheme_method_exposure(monkeypatch) -> None:
    """HTTPS is clean, HTTP exposes dangerous methods - finding only on HTTP."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, POST",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, PUT, DELETE, PROPFIND",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    dangerous_findings = [
        f for f in result.findings
        if f.rule_id == "external.allow_header_dangerous_methods"
    ]
    assert len(dangerous_findings) == 1
    assert "http://example.com/" in dangerous_findings[0].location.target

    webdav_findings = [
        f for f in result.findings
        if f.rule_id == "external.webdav_methods_exposed"
    ]
    assert len(webdav_findings) == 1
    assert "http://example.com/" in webdav_findings[0].location.target


# ---------------------------------------------------------------------------
# HEAD->GET fallback preserving Allow header with dangerous methods
# ---------------------------------------------------------------------------


def test_allow_header_dangerous_methods_via_head_get_fallback(monkeypatch) -> None:
    """Allow header preserved from HEAD 405 fallback triggers dangerous method rule.

    Simulates the real probe path: HEAD returns 405 with an Allow header
    containing dangerous methods, GET succeeds, and _preserve_head_allow_header
    copies the Allow value onto the final ProbeAttempt.
    """
    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")
    methods_called: list[str] = []

    def fake_try_http_method(probe_target: ProbeTarget, method: str) -> ProbeAttempt:
        methods_called.append(method)
        if method == "HEAD":
            return ProbeAttempt(
                target=probe_target,
                tcp_open=True,
                effective_method="HEAD",
                status_code=405,
                reason_phrase="Method Not Allowed",
                server_header="nginx",
                allow_header="GET, HEAD, PUT, DELETE, CONNECT",
            )
        return ProbeAttempt(
            target=probe_target,
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        )

    monkeypatch.setattr("webconf_audit.external.recon._build_probe_targets", lambda _: [target])
    monkeypatch.setattr("webconf_audit.external.recon._is_tcp_port_open", lambda h, p: True)
    monkeypatch.setattr("webconf_audit.external.recon._try_http_method", fake_try_http_method)
    monkeypatch.setattr(
        "webconf_audit.external.recon._try_options_request",
        lambda probe_target: OptionsObservation(),
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        lambda successful_attempts, identification=None: [],
    )
    monkeypatch.setattr("webconf_audit.external.recon._probe_error_pages", lambda _: [])
    monkeypatch.setattr("webconf_audit.external.recon._probe_malformed_requests", lambda _: [])

    result = analyze_external_target("example.com")
    rule_ids = {f.rule_id for f in result.findings}
    assert methods_called == ["HEAD", "GET"]
    assert "external.allow_header_dangerous_methods" in rule_ids
    finding = next(
        f for f in result.findings
        if f.rule_id == "external.allow_header_dangerous_methods"
    )
    assert "PUT" in finding.description
    assert "DELETE" in finding.description
    assert "CONNECT" in finding.description
    assert "Allow: GET, HEAD, PUT, DELETE, CONNECT" in finding.location.details


# ---------------------------------------------------------------------------
# --- TLS 1.0 supported rule (active probing) ---
# ---------------------------------------------------------------------------


def test_tls_1_0_supported_fires(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1", "TLSv1.2", "TLSv1.3"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_0_supported" in {f.rule_id for f in result.findings}


def test_tls_1_0_supported_does_not_fire_when_absent(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1.2", "TLSv1.3"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_0_supported" not in {f.rule_id for f in result.findings}


def test_tls_1_0_supported_does_not_fire_empty_protocols(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=())
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_0_supported" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# --- TLS 1.1 supported rule (active probing) ---
# ---------------------------------------------------------------------------


def test_tls_1_1_supported_fires(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1.1", "TLSv1.2", "TLSv1.3"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_1_supported" in {f.rule_id for f in result.findings}


def test_tls_1_1_supported_does_not_fire_when_absent(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1.2", "TLSv1.3"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_1_supported" not in {f.rule_id for f in result.findings}


def test_tls_1_1_supported_severity_is_medium(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1.1", "TLSv1.2"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.tls_1_1_supported")
    assert finding.severity == "medium"


# ---------------------------------------------------------------------------
# --- TLS 1.3 not supported rule ---
# ---------------------------------------------------------------------------


def test_tls_1_3_not_supported_fires(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", supported_protocols=("TLSv1.2",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_3_not_supported" in {f.rule_id for f in result.findings}


def test_tls_1_3_not_supported_does_not_fire_when_supported(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1.2", "TLSv1.3"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_3_not_supported" not in {f.rule_id for f in result.findings}


def test_tls_1_3_not_supported_skips_empty_protocols(monkeypatch) -> None:
    """When active probing did not run, do not fire this rule."""
    tls = TLSInfo(protocol_version="TLSv1.2", supported_protocols=())
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_3_not_supported" not in {f.rule_id for f in result.findings}


def test_tls_1_3_not_supported_severity_is_low(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", supported_protocols=("TLSv1.2",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.tls_1_3_not_supported")
    assert finding.severity == "low"


# ---------------------------------------------------------------------------
# --- Weak cipher suite rule ---
# ---------------------------------------------------------------------------


def test_weak_cipher_fires_for_rc4(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="RC4-SHA")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" in {f.rule_id for f in result.findings}


def test_weak_cipher_fires_for_des(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="DES-CBC3-SHA")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.weak_cipher_suite" in rule_ids


def test_weak_cipher_fires_for_null(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="NULL-SHA256")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" in {f.rule_id for f in result.findings}


def test_weak_cipher_fires_for_export(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="EXP-RC4-MD5")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.weak_cipher_suite" in rule_ids


def test_weak_cipher_does_not_fire_for_aes_gcm(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" not in {f.rule_id for f in result.findings}


def test_weak_cipher_does_not_fire_for_chacha20(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cipher_name="TLS_CHACHA20_POLY1305_SHA256")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" not in {f.rule_id for f in result.findings}


def test_weak_cipher_does_not_fire_when_cipher_absent(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" not in {f.rule_id for f in result.findings}


def test_weak_cipher_description_lists_matched_keywords(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="EXP-RC4-MD5")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.weak_cipher_suite")
    assert "RC4" in finding.description
    assert "EXP" in finding.description
    assert "MD5" in finding.description


# ---------------------------------------------------------------------------
# --- Deeper TLS runtime posture rules ---
# ---------------------------------------------------------------------------


def test_forward_secrecy_not_observed_fires_for_tls12_static_rsa_cipher(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="AES128-GCM-SHA256")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_forward_secrecy_not_observed" in {f.rule_id for f in result.findings}


def test_forward_secrecy_not_observed_skips_ecdhe_cipher(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="ECDHE-RSA-AES128-GCM-SHA256")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_forward_secrecy_not_observed" not in {f.rule_id for f in result.findings}


def test_forward_secrecy_not_observed_skips_tls13_cipher(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_forward_secrecy_not_observed" not in {f.rule_id for f in result.findings}


def test_server_cipher_preference_not_observed_fires(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cipher_name="ECDHE-RSA-AES128-GCM-SHA256",
        server_cipher_preference=False,
        cipher_preference_first_cipher="ECDHE-RSA-AES128-GCM-SHA256",
        cipher_preference_reversed_cipher="AES128-GCM-SHA256",
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_server_cipher_preference_not_observed" in {f.rule_id for f in result.findings}


def test_server_cipher_preference_not_observed_skips_when_server_order(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cipher_name="ECDHE-RSA-AES128-GCM-SHA256",
        server_cipher_preference=True,
        cipher_preference_first_cipher="ECDHE-RSA-AES128-GCM-SHA256",
        cipher_preference_reversed_cipher="ECDHE-RSA-AES128-GCM-SHA256",
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_server_cipher_preference_not_observed" not in {f.rule_id for f in result.findings}


def test_server_cipher_preference_not_observed_skips_indeterminate(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", server_cipher_preference=None)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_server_cipher_preference_not_observed" not in {f.rule_id for f in result.findings}


def test_ocsp_stapling_not_observed_fires(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", ocsp_stapled=False)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.ocsp_stapling_not_observed" in {f.rule_id for f in result.findings}


def test_ocsp_stapling_not_observed_skips_when_stapled(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", ocsp_stapled=True)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.ocsp_stapling_not_observed" not in {f.rule_id for f in result.findings}


def test_ocsp_stapling_not_observed_skips_indeterminate(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", ocsp_stapled=None)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.ocsp_stapling_not_observed" not in {f.rule_id for f in result.findings}


def test_tls_runtime_depth_info_in_metadata(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cipher_name="ECDHE-RSA-AES128-GCM-SHA256",
        server_cipher_preference=True,
        cipher_preference_first_cipher="ECDHE-RSA-AES128-GCM-SHA256",
        cipher_preference_reversed_cipher="ECDHE-RSA-AES128-GCM-SHA256",
        ocsp_stapled=True,
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["server_cipher_preference"] is True
    assert tls_meta["cipher_preference_first_cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert tls_meta["cipher_preference_reversed_cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert tls_meta["ocsp_stapled"] is True


# ---------------------------------------------------------------------------
# --- Certificate chain incomplete rule ---
# ---------------------------------------------------------------------------


def test_cert_chain_incomplete_fires(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_chain_complete=False,
        cert_chain_error="certificate verify failed: unable to get local issuer certificate",
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cert_chain_incomplete" in {f.rule_id for f in result.findings}


def test_cert_chain_incomplete_does_not_fire_when_verified(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_complete=True)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cert_chain_incomplete" not in {f.rule_id for f in result.findings}


def test_cert_chain_incomplete_skips_when_none(monkeypatch) -> None:
    """When chain verification did not run, do not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_complete=None)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cert_chain_incomplete" not in {f.rule_id for f in result.findings}


def test_cert_chain_incomplete_includes_error_in_description(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_chain_complete=False,
        cert_chain_error="self-signed certificate",
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.cert_chain_incomplete")
    assert "self-signed certificate" in finding.description


def test_cert_chain_incomplete_does_not_fire_on_indeterminate(monkeypatch) -> None:
    """When chain verification is indeterminate (None), do not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_complete=None)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cert_chain_incomplete" not in {f.rule_id for f in result.findings}


def test_cert_chain_incomplete_does_not_overlap_with_san_mismatch(monkeypatch) -> None:
    """SAN mismatch with a valid trust chain should NOT trigger cert_chain_incomplete.

    This verifies that verify_certificate_chain uses check_hostname=False,
    so hostname mismatch alone does not produce a false chain_incomplete finding.
    """
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_san=("other.com",),
        cert_chain_complete=True,  # chain is fine, hostname mismatches
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_san_mismatch" in rule_ids
    assert "external.cert_chain_incomplete" not in rule_ids


def test_cert_chain_incomplete_does_not_fire_on_expired_cert(monkeypatch) -> None:
    """An expired certificate should fire certificate_expired but NOT cert_chain_incomplete.

    Expired leaf certs are a validity issue, not a chain-completeness issue.
    verify_certificate_chain treats expiry as indeterminate (cert_chain_complete=None).
    """
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_not_after="Jan  1 00:00:00 2020 GMT",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Test CA",
        cert_chain_complete=None,  # expired → indeterminate for chain
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.certificate_expired" in rule_ids
    assert "external.cert_chain_incomplete" not in rule_ids


# ---------------------------------------------------------------------------
# --- Certificate chain length unusual rule ---
# ---------------------------------------------------------------------------


def test_cert_chain_length_unusual_fires_for_leaf_only(monkeypatch) -> None:
    """depth=1 (leaf-only, no intermediates) must fire the rule."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=1)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" in rule_ids


def test_cert_chain_length_unusual_leaf_only_description(monkeypatch) -> None:
    """depth=1 finding description must mention 'intermediate'."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=1)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.cert_chain_length_unusual")
    assert "intermediate" in finding.description.lower()


def test_cert_chain_length_unusual_fires_for_depth_five(monkeypatch) -> None:
    """depth=5 exceeds max of 4 — rule must fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=5)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" in rule_ids


def test_cert_chain_length_unusual_long_chain_description(monkeypatch) -> None:
    """depth > max finding description must mention depth value."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=6)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.cert_chain_length_unusual")
    assert "6" in finding.description


def test_cert_chain_length_unusual_does_not_fire_for_depth_two(monkeypatch) -> None:
    """depth=2 (leaf + one intermediate) is normal — rule must not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=2)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" not in rule_ids


def test_cert_chain_length_unusual_does_not_fire_for_depth_three(monkeypatch) -> None:
    """depth=3 is within normal range — rule must not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=3)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" not in rule_ids


def test_cert_chain_length_unusual_does_not_fire_for_depth_four(monkeypatch) -> None:
    """depth=4 is at the boundary (allowed) — rule must not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=4)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" not in rule_ids


def test_cert_chain_length_unusual_skips_when_none(monkeypatch) -> None:
    """depth=None (probe failed) must not fire the rule."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=None)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" not in rule_ids


def test_cert_chain_length_unusual_severity_is_low(monkeypatch) -> None:
    """Rule severity must be 'low' (informational misconfiguration signal)."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=1)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.cert_chain_length_unusual")
    assert finding.severity == "low"


def test_cert_chain_length_unusual_does_not_fire_for_depth_zero(monkeypatch) -> None:
    """depth=0 (no certs received, indeterminate) must not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=0)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" not in rule_ids


def test_no_duplicate_tls_legacy_and_active_probe_findings(monkeypatch) -> None:
    """The removed external.tls_legacy_protocol must never appear in findings."""
    tls = TLSInfo(
        protocol_version="TLSv1",
        supported_protocols=("TLSv1", "TLSv1.2"),
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.tls_legacy_protocol" not in rule_ids
    assert "external.tls_1_0_supported" in rule_ids


# ---------------------------------------------------------------------------
# --- Certificate SAN mismatch rule ---
# ---------------------------------------------------------------------------


def test_cert_san_mismatch_fires(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("other.com", "www.other.com"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    assert "external.cert_san_mismatch" in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_does_not_fire_exact_match(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("example.com", "www.example.com"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    assert "external.cert_san_mismatch" not in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_does_not_fire_wildcard_match(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("*.example.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="www.example.com")
    assert "external.cert_san_mismatch" not in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_wildcard_does_not_match_apex(monkeypatch) -> None:
    """*.example.com should NOT match example.com itself."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("*.example.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    assert "external.cert_san_mismatch" in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_wildcard_does_not_match_nested(monkeypatch) -> None:
    """*.example.com should NOT match a.b.example.com."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("*.example.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="a.b.example.com")
    assert "external.cert_san_mismatch" in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_case_insensitive(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("Example.COM",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    assert "external.cert_san_mismatch" not in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_skips_empty_san(monkeypatch) -> None:
    """When SAN list is empty, do not fire (no data to compare)."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=())
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    assert "external.cert_san_mismatch" not in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_with_url_target(monkeypatch) -> None:
    """When target is a full URL, hostname is extracted correctly."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("other.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls)]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="https://example.com/path")
    assert "external.cert_san_mismatch" in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_with_host_port_target(monkeypatch) -> None:
    """When target is host:port, hostname is extracted correctly."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("other.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls)]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com:8443")
    assert "external.cert_san_mismatch" in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_skips_ip_literal_targets(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("example.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls)]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="192.0.2.10")
    assert "external.cert_san_mismatch" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# --- _hostname_matches_san unit tests ---
# ---------------------------------------------------------------------------


def test_hostname_matches_san_exact() -> None:
    assert hostname_matches_san("example.com", ("example.com",)) is True


def test_hostname_matches_san_case_insensitive() -> None:
    assert hostname_matches_san("example.com", ("EXAMPLE.COM",)) is True


def test_hostname_matches_san_normalizes_hostname_case() -> None:
    assert hostname_matches_san("WWW.Example.com", ("*.example.com",)) is True


def test_hostname_matches_san_wildcard_one_level() -> None:
    assert hostname_matches_san("www.example.com", ("*.example.com",)) is True


def test_hostname_matches_san_wildcard_does_not_match_apex() -> None:
    assert hostname_matches_san("example.com", ("*.example.com",)) is False


def test_hostname_matches_san_wildcard_does_not_match_nested() -> None:
    assert hostname_matches_san("a.b.example.com", ("*.example.com",)) is False


def test_hostname_matches_san_no_match() -> None:
    assert hostname_matches_san("evil.com", ("example.com", "*.example.com")) is False


def test_hostname_matches_san_empty_entries() -> None:
    assert hostname_matches_san("example.com", ()) is False


def test_hostname_matches_san_multiple_entries() -> None:
    assert hostname_matches_san("api.example.com", ("example.com", "*.example.com")) is True


def test_parse_cert_date_returns_utc_for_gmt_timestamp() -> None:
    parsed = _parse_cert_date("Mar 15 12:00:00 2026 GMT")
    assert parsed is not None
    assert parsed.tzinfo == timezone.utc
    assert parsed.isoformat() == "2026-03-15T12:00:00+00:00"


def test_parse_cert_date_rejects_unknown_timezone() -> None:
    assert _parse_cert_date("Mar 15 12:00:00 2026 PST") is None


# ---------------------------------------------------------------------------
# --- Combination / edge-case tests for 1.2 block ---
# ---------------------------------------------------------------------------


def test_tls_1_0_and_1_1_both_fire(monkeypatch) -> None:
    """When both TLS 1.0 and 1.1 are supported, both rules fire."""
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        supported_protocols=("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"),
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.tls_1_0_supported" in rule_ids
    assert "external.tls_1_1_supported" in rule_ids
    assert "external.tls_1_3_not_supported" not in rule_ids


def test_weak_cipher_adh_no_anon_keyword(monkeypatch) -> None:
    """ADH cipher name doesn't literally contain 'anon', verify no false positive."""
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="ADH-AES256-SHA")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" not in {f.rule_id for f in result.findings}


def test_weak_cipher_null_in_name(monkeypatch) -> None:
    """AECDH-NULL-SHA contains NULL keyword."""
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="AECDH-NULL-SHA")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" in {f.rule_id for f in result.findings}


def test_chain_incomplete_and_san_mismatch_both_fire(monkeypatch) -> None:
    """Multiple TLS issues on the same endpoint should all fire."""
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_san=("other.com",),
        cert_chain_complete=False,
        cert_chain_error="self-signed certificate",
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_incomplete" in rule_ids
    assert "external.cert_san_mismatch" in rule_ids


def test_tls_info_default_values() -> None:
    """Verify all new TLSInfo fields have correct defaults."""
    tls = TLSInfo()
    assert tls.cipher_name is None
    assert tls.cipher_bits is None
    assert tls.cipher_protocol is None
    assert tls.cert_san == ()
    assert tls.supported_protocols == ()
    assert tls.cert_chain_complete is None
    assert tls.cert_chain_error is None


def test_tls_info_metadata_includes_all_new_fields(monkeypatch) -> None:
    """Metadata dict for TLSInfo should contain all 1.2 fields."""
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        cipher_protocol="TLSv1.3",
        cert_san=("example.com", "www.example.com"),
        supported_protocols=("TLSv1.2", "TLSv1.3"),
        cert_chain_complete=True,
        cert_chain_error=None,
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["cipher_name"] == "TLS_AES_256_GCM_SHA384"
    assert tls_meta["cipher_bits"] == 256
    assert tls_meta["cipher_protocol"] == "TLSv1.3"
    assert tls_meta["cert_san"] == ["example.com", "www.example.com"]
    assert tls_meta["supported_protocols"] == ["TLSv1.2", "TLSv1.3"]
    assert tls_meta["cert_chain_complete"] is True
    assert tls_meta["cert_chain_error"] is None


def test_no_tls_rules_fire_for_http_only(monkeypatch) -> None:
    """HTTP-only probes should not trigger any TLS rules."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_rule_ids = {
        f.rule_id for f in result.findings
        if f.rule_id.startswith("external.tls_")
        or f.rule_id.startswith("external.cert_")
        or f.rule_id == "external.weak_cipher_suite"
    }
    assert tls_rule_ids == set()


# ---------------------------------------------------------------------------
# 1.3.1 — Error page fingerprinting
# ---------------------------------------------------------------------------
