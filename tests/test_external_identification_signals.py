from tests.external_helpers import (
    ErrorPageProbe,
    MalformedRequestProbe,
    ProbeAttempt,
    ProbeTarget,
    TLSInfo,
    _ALL_SECURITY_HEADERS,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    _match_error_page_body,
    _match_malformed_response_body,
    _parse_malformed_response,
    _sensitive_path_probe,
)

def test_match_error_page_body_nginx_center_tag() -> None:
    body = "<html><body><center>nginx</center></body></html>"
    assert _match_error_page_body(body) == "nginx"


def test_match_error_page_body_nginx_with_version() -> None:
    body = '<hr><center>nginx/1.24.0</center></body>'
    assert _match_error_page_body(body) == "nginx"


def test_match_error_page_body_openresty() -> None:
    body = "<html><body><center>openresty/1.21.4.3</center></body></html>"
    assert _match_error_page_body(body) == "nginx"


def test_match_error_page_body_apache() -> None:
    body = '<address>Apache Server at example.com Port 80</address>'
    assert _match_error_page_body(body) == "apache"


def test_match_error_page_body_apache_version_string() -> None:
    body = '<p>Apache/2.4.58 (Ubuntu) Server</p>'
    assert _match_error_page_body(body) == "apache"


def test_match_error_page_body_lighttpd() -> None:
    body = '<p>powered by lighttpd</p>'
    assert _match_error_page_body(body) == "lighttpd"


def test_match_error_page_body_lighttpd_version() -> None:
    body = '<h1>404 Not Found</h1><p>lighttpd/1.4.71</p>'
    assert _match_error_page_body(body) == "lighttpd"


def test_match_error_page_body_iis_detailed() -> None:
    body = '<h2>IIS Detailed Error - 404.0 - Not Found</h2>'
    assert _match_error_page_body(body) == "iis"


def test_match_error_page_body_iis_server_error_in() -> None:
    body = "<h1>Server Error in '/' Application.</h1>"
    assert _match_error_page_body(body) == "iis"


def test_match_error_page_body_iis_version_string() -> None:
    body = '<p>Microsoft-IIS/10.0</p>'
    assert _match_error_page_body(body) == "iis"


def test_match_error_page_body_no_match() -> None:
    body = '<html><body><h1>404 Not Found</h1></body></html>'
    assert _match_error_page_body(body) is None


def test_match_error_page_body_empty() -> None:
    assert _match_error_page_body("") is None


# --- Integration: error page evidence wired into identification ---


def test_error_page_nginx_contributes_to_identification_when_no_server_header(
    monkeypatch,
) -> None:
    """Error page body alone (no Server header) should produce identification."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<html><body><center>nginx/1.24.0</center></body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    # Single error page vote → low confidence (moderate evidence, not strong).
    assert ident["confidence"] == "low"
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "error_page_body" in evidence_signals


def test_error_page_evidence_reinforces_server_header(monkeypatch) -> None:
    """Error page body + Server header → both appear in evidence."""
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
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<html><body><center>nginx</center></body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "server_header" in evidence_signals
    assert "error_page_body" in evidence_signals


def test_error_page_iis_identification(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet='<h2>IIS Detailed Error - 404.0 - Not Found</h2>',
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "iis"


def test_error_page_lighttpd_identification(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<h1>404 Not Found</h1><p>lighttpd/1.4.71</p>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "lighttpd"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "lighttpd"
    assert ident["confidence"] == "low"


def test_error_page_no_body_does_not_add_evidence(monkeypatch) -> None:
    """Error page with None body should not create evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet=None,
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    # No Server header + no error page match → unknown.
    assert result.server_type is None


def test_error_page_unrecognized_body_does_not_add_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<html><body>Custom 404 page</body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )
    assert result.server_type is None


def test_error_page_status_200_does_not_add_evidence(monkeypatch) -> None:
    """Only actual error responses should contribute error-page evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=200,
            body_snippet="<html><body><center>nginx</center></body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type is None
    evidence_signals = [e["signal"] for e in result.metadata["server_identification"]["evidence"]]
    assert "error_page_body" not in evidence_signals


def test_error_page_metadata_present(monkeypatch) -> None:
    """Error page probes appear in metadata."""
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
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            server_header="nginx",
            body_snippet="<center>nginx</center>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert "error_page_probes" in result.metadata
    ep_meta = result.metadata["error_page_probes"]
    assert len(ep_meta) == 1
    assert ep_meta[0]["status_code"] == 404
    assert ep_meta[0]["server_header"] == "nginx"


def test_error_page_conflicting_with_server_header_strong_wins(
    monkeypatch,
) -> None:
    """Error page says IIS but Server header says nginx → strong signal wins."""
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
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet='<h2>IIS Detailed Error - 404.0</h2>',
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    # Server header is strong/direct evidence → takes precedence over error page.
    # Error page evidence is still collected but doesn't override.
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    assert ident["confidence"] == "high"
    # Both evidence entries are preserved for traceability.
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "server_header" in evidence_signals
    assert "error_page_body" in evidence_signals


def test_error_page_probe_error_does_not_crash(monkeypatch) -> None:
    """Error page probe that failed with OSError should not crash pipeline."""
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
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            error_message="Connection reset by peer",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    # Should still identify via server header.
    assert result.server_type == "nginx"


# ---------------------------------------------------------------------------
# 1.3.2 — Malformed request fingerprinting
# ---------------------------------------------------------------------------

# --- Unit: _match_malformed_response_body ---


def test_match_malformed_body_nginx() -> None:
    body = "<html><body><center>nginx</center></body></html>"
    assert _match_malformed_response_body(body) == "nginx"


def test_match_malformed_body_apache_your_browser() -> None:
    body = "Your browser sent a request that this server could not understand."
    assert _match_malformed_response_body(body) == "apache"


def test_match_malformed_body_iis_bad_request() -> None:
    body = "<h2>Bad Request - Invalid URL</h2>"
    assert _match_malformed_response_body(body) == "iis"


def test_match_malformed_body_lighttpd() -> None:
    body = "<p>lighttpd/1.4.71</p>"
    assert _match_malformed_response_body(body) == "lighttpd"


def test_match_malformed_body_no_match() -> None:
    assert _match_malformed_response_body("<h1>400 Bad Request</h1>") is None


def test_match_malformed_body_empty() -> None:
    assert _match_malformed_response_body("") is None


# --- Unit: _parse_malformed_response ---


def test_parse_malformed_response_full() -> None:
    raw = (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><body><center>nginx</center></body></html>"
    )
    result = _parse_malformed_response("https://example.com/", raw)
    assert result.status_code == 400
    assert result.reason_phrase == "Bad Request"
    assert result.server_header == "nginx/1.24.0"
    assert result.body_snippet is not None
    assert "nginx" in result.body_snippet


def test_parse_malformed_response_no_body() -> None:
    raw = b"HTTP/1.1 400 Bad Request\r\nServer: Apache\r\n\r\n"
    result = _parse_malformed_response("https://example.com/", raw)
    assert result.status_code == 400
    assert result.server_header == "Apache"
    assert result.body_snippet is None


def test_parse_malformed_response_no_headers_separator() -> None:
    raw = b"HTTP/1.1 400 Bad Request"
    result = _parse_malformed_response("https://example.com/", raw)
    # No \r\n\r\n separator → entire response treated as body snippet.
    assert result.body_snippet is not None


def test_parse_malformed_response_iis_style() -> None:
    raw = (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Server: Microsoft-IIS/10.0\r\n"
        b"\r\n"
        b"<h2>Bad Request - Invalid URL</h2>"
    )
    result = _parse_malformed_response("https://example.com/", raw)
    assert result.status_code == 400
    assert result.server_header == "Microsoft-IIS/10.0"
    assert "Bad Request - Invalid URL" in (result.body_snippet or "")


def test_parse_malformed_response_empty_bytes() -> None:
    result = _parse_malformed_response("https://example.com/", b"")
    assert result.status_code is None
    assert result.body_snippet is None


# --- Integration: malformed request evidence in identification ---


def test_malformed_server_header_contributes_strong_evidence(monkeypatch) -> None:
    """Malformed response Server header should produce strong/direct evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            reason_phrase="Bad Request",
            server_header="nginx/1.24.0",
            body_snippet="<html><body>400 Bad Request</body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    # Server header from malformed response is strong → high confidence.
    assert ident["confidence"] == "high"
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "malformed_response_server_header" in evidence_signals


def test_malformed_body_only_contributes_moderate_evidence(monkeypatch) -> None:
    """Malformed response body (no Server header) → moderate/low evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            reason_phrase="Bad Request",
            body_snippet="Your browser sent a request that this server could not understand.",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "apache"
    ident = result.metadata["server_identification"]
    # Body-only → low confidence (moderate evidence, single vote).
    assert ident["confidence"] == "low"
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "malformed_response_body" in evidence_signals


def test_malformed_body_iis_contributes_moderate_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            reason_phrase="Bad Request",
            body_snippet="<h2>Bad Request - Invalid URL</h2>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "low"
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "malformed_response_body" in evidence_signals


def test_malformed_server_header_plus_body_both_evidence(monkeypatch) -> None:
    """Malformed response with both Server header and body match → two evidence entries."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            server_header="nginx/1.24.0",
            body_snippet="<html><body><center>nginx</center></body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "malformed_response_server_header" in evidence_signals
    assert "malformed_response_body" in evidence_signals


def test_malformed_reinforces_normal_server_header(monkeypatch) -> None:
    """Normal Server header + malformed Server header → both evidence, high confidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            server_header="Apache/2.4.58",
            body_snippet="Apache Server at example.com Port 443",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "apache"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "high"


def test_malformed_no_body_no_server_header_no_evidence(monkeypatch) -> None:
    """Malformed probe with no useful data should not add evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            body_snippet="<h1>400</h1>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )
    assert result.server_type is None


def test_malformed_status_200_does_not_add_evidence(monkeypatch) -> None:
    """Malformed-response fingerprinting must ignore non-error responses."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=200,
            server_header="Apache/2.4.58",
            body_snippet="Apache Server at example.com Port 443",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type is None
    evidence_signals = [e["signal"] for e in result.metadata["server_identification"]["evidence"]]
    assert "malformed_response_server_header" not in evidence_signals
    assert "malformed_response_body" not in evidence_signals


def test_malformed_probe_error_does_not_crash(monkeypatch) -> None:
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
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            error_message="Connection reset",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )
    assert result.server_type == "nginx"


def test_try_malformed_request_probe_unicode_host_uses_idna(monkeypatch) -> None:
    from webconf_audit.external.recon import _try_malformed_request_probe

    class DummySock:
        def __init__(self) -> None:
            self.sent = b""

        def sendall(self, data: bytes) -> None:
            self.sent = data

        def recv(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            return None

    dummy = DummySock()
    monkeypatch.setattr(
        "webconf_audit.external.recon.socket.create_connection",
        lambda *_args, **_kwargs: dummy,
    )

    host = "\u0442\u0435\u0441\u0442.\u0440\u0444"
    result = _try_malformed_request_probe(
        ProbeTarget(scheme="http", host=host, port=80, path="/"),
    )

    assert result.error_message is None
    assert host.encode("idna") in dummy.sent


def test_malformed_metadata_present(monkeypatch) -> None:
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
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            reason_phrase="Bad Request",
            server_header="nginx/1.24.0",
            body_snippet="<center>nginx</center>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert "malformed_request_probes" in result.metadata
    mp_meta = result.metadata["malformed_request_probes"]
    assert len(mp_meta) == 1
    assert mp_meta[0]["status_code"] == 400
    assert mp_meta[0]["reason_phrase"] == "Bad Request"
    assert mp_meta[0]["server_header"] == "nginx/1.24.0"


# ---------------------------------------------------------------------------
# 1.3.3 — Extended header fingerprinting
# ---------------------------------------------------------------------------


def test_x_aspnetmvc_version_contributes_iis_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_aspnetmvc_version_header="5.2",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "x_aspnetmvc_version_header" in evidence_signals
    # Single moderate vote → low confidence.
    assert ident["confidence"] == "low"


def test_x_aspnetmvc_version_reinforces_aspnet_version(monkeypatch) -> None:
    """Both X-AspNet-Version and X-AspNetMvc-Version → medium confidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_powered_by_header="ASP.NET",
            x_aspnet_version_header="4.0.30319",
            x_aspnetmvc_version_header="5.2",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "medium"
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "x_aspnetmvc_version_header" in evidence_signals
    assert "x_aspnet_version_header" in evidence_signals
    assert "x_powered_by_header" in evidence_signals


def test_set_cookie_aspnet_session_contributes_iis_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            set_cookie_headers=("ASP.NET_SessionId=abc123; path=/; HttpOnly",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "set_cookie_session" in evidence_signals


def test_set_cookie_aspxauth_contributes_iis_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            set_cookie_headers=(".ASPXAUTH=DEADBEEF; path=/; secure; HttpOnly",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    evidence_signals = [e["signal"] for e in result.metadata["server_identification"]["evidence"]]
    assert "set_cookie_session" in evidence_signals


def test_set_cookie_non_aspnet_does_not_create_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            set_cookie_headers=("PHPSESSID=abc123; path=/",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    # PHPSESSID is not an IIS indicator; no evidence should be created.
    assert result.server_type is None


def test_via_header_nginx_creates_weak_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            via_header="1.1 nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    ident = result.metadata["server_identification"]
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "via_header" in evidence_signals
    via_evidence = [e for e in ident["evidence"] if e["signal"] == "via_header"][0]
    assert via_evidence["indicates"] == "nginx"
    assert via_evidence["strength"] == "weak"
    # Via alone is weak → no vote → server_type is None.
    assert result.server_type is None


def test_via_header_apache_creates_weak_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            via_header="1.1 Apache/2.4.58",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    ident = result.metadata["server_identification"]
    via_evidence = [e for e in ident["evidence"] if e["signal"] == "via_header"]
    assert len(via_evidence) == 1
    assert via_evidence[0]["indicates"] == "apache"


def test_via_header_unrecognized_no_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            via_header="1.1 varnish",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    ident = result.metadata["server_identification"]
    via_evidence = [e for e in ident["evidence"] if e["signal"] == "via_header"]
    assert len(via_evidence) == 0


def test_new_headers_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            x_aspnetmvc_version_header="5.2",
            via_header="1.1 proxy",
            etag_header='"abc123"',
            cache_control_header="no-store",
            x_dns_prefetch_control_header="off",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    meta = result.metadata["probe_attempts"][0]
    assert meta["x_aspnetmvc_version_header"] == "5.2"
    assert meta["via_header"] == "1.1 proxy"
    assert meta["etag_header"] == '"abc123"'
    assert meta["cache_control_header"] == "no-store"
    assert meta["x_dns_prefetch_control_header"] == "off"
    assert meta["cross_origin_embedder_policy_header"] == "require-corp"
    assert meta["cross_origin_opener_policy_header"] == "same-origin"
    assert meta["cross_origin_resource_policy_header"] == "same-origin"


def test_new_headers_in_diagnostics(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            x_aspnetmvc_version_header="5.2",
            via_header="1.1 proxy",
            etag_header='"abc123"',
            cache_control_header="no-store",
            x_dns_prefetch_control_header="off",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert any("x_aspnetmvc_version: 5.2" in d for d in result.diagnostics)
    assert any("via: 1.1 proxy" in d for d in result.diagnostics)
    assert any('etag: "abc123"' in d for d in result.diagnostics)
    assert any("cache_control: no-store" in d for d in result.diagnostics)
    assert any("x_dns_prefetch_control: off" in d for d in result.diagnostics)
    assert any("cross_origin_embedder_policy: require-corp" in d for d in result.diagnostics)
    assert any("cross_origin_opener_policy: same-origin" in d for d in result.diagnostics)
    assert any("cross_origin_resource_policy: same-origin" in d for d in result.diagnostics)


def test_phase1_external_enrichment_metadata_is_present_together(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        cipher_protocol="TLSv1.3",
        cert_san=("example.com", "www.example.com"),
        supported_protocols=("TLSv1.2", "TLSv1.3"),
        cert_chain_complete=True,
    )
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx/1.24.0",
            tls_info=tls,
            x_powered_by_header="PHP/8.2",
            x_aspnetmvc_version_header="5.2",
            via_header="1.1 proxy",
            etag_header='"abc123"',
            cache_control_header="no-store",
            x_dns_prefetch_control_header="off",
            body_snippet="Welcome to nginx!",
        ),
        _http_redirect_probe(location_header="https://example.com/app"),
    ]
    additional_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/app"),
            server_header="nginx/1.24.0",
        ),
    ]
    sensitive = [
        _sensitive_path_probe("/.env", body_snippet="APP_ENV=production"),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            server_header="nginx/1.24.0",
            body_snippet="<center>nginx</center>",
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            server_header="nginx/1.24.0",
            body_snippet="<center>nginx</center>",
        ),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=sensitive,
        error_page_probes=error_pages,
        malformed_request_probes=malformed,
        additional_probe_attempts=additional_attempts,
    )

    assert result.metadata["probe_attempts"][0]["tls_info"]["supported_protocols"] == [
        "TLSv1.2",
        "TLSv1.3",
    ]
    assert result.metadata["probe_attempts"][0]["cross_origin_embedder_policy_header"] == "require-corp"
    assert result.metadata["probe_attempts"][0]["cache_control_header"] == "no-store"
    assert result.metadata["server_identification"]["server_type"] == "nginx"
    assert result.metadata["error_page_probes"][0]["status_code"] == 404
    assert result.metadata["malformed_request_probes"][0]["status_code"] == 400
    assert result.metadata["sensitive_path_probes"][0]["path"] == "/.env"
    assert result.metadata["redirect_chains"][0]["final_url"] == "https://example.com/app"


def test_multiple_aspnet_signals_accumulate(monkeypatch) -> None:
    """X-AspNet-Version + X-AspNetMvc-Version + Set-Cookie ASP.NET → IIS medium."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_aspnet_version_header="4.0.30319",
            x_aspnetmvc_version_header="5.2",
            set_cookie_headers=("ASP.NET_SessionId=abc; path=/",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "medium"


# ---------------------------------------------------------------------------
# 1.3.4 — Cross-signal integration and priority chain tests
# ---------------------------------------------------------------------------


def test_all_signals_agree_nginx(monkeypatch) -> None:
    """Server header + error page + malformed response all say nginx → high."""
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
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<center>nginx</center>",
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            server_header="nginx/1.24.0",
            body_snippet="<center>nginx</center>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=error_pages,
        malformed_request_probes=malformed,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "high"
    assert ident["ambiguous"] is False
    signals = {e["signal"] for e in ident["evidence"]}
    assert "server_header" in signals
    assert "error_page_body" in signals
    assert "malformed_response_server_header" in signals
    assert "malformed_response_body" in signals


def test_all_signals_agree_iis(monkeypatch) -> None:
    """IIS: Server header + X-AspNet + X-AspNetMvc + Set-Cookie + error page."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Microsoft-IIS/10.0",
            x_powered_by_header="ASP.NET",
            x_aspnet_version_header="4.0.30319",
            x_aspnetmvc_version_header="5.2",
            set_cookie_headers=("ASP.NET_SessionId=abc; path=/",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<h2>IIS Detailed Error - 404.0</h2>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "high"
    signals = {e["signal"] for e in ident["evidence"]}
    assert signals >= {
        "server_header",
        "x_powered_by_header",
        "x_aspnet_version_header",
        "x_aspnetmvc_version_header",
        "set_cookie_session",
        "error_page_body",
    }


def test_priority_direct_beats_error_page(monkeypatch) -> None:
    """Direct server header (nginx) should win over error page body (apache)."""
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
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="Apache Server at example.com Port 443",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "nginx"
    assert result.metadata["server_identification"]["confidence"] == "high"


def test_priority_direct_beats_malformed_body(monkeypatch) -> None:
    """Direct server header (apache) should win over malformed body (iis)."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            body_snippet="Bad Request - Invalid URL",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "apache"
    assert result.metadata["server_identification"]["confidence"] == "high"


def test_priority_error_page_beats_app_stack(monkeypatch) -> None:
    """Error page body (nginx) should win over app_stack only (iis via X-AspNet)."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_aspnet_version_header="4.0.30319",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<center>nginx</center>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "nginx"


def test_new_signals_improve_confidence_with_weak_server_header(monkeypatch) -> None:
    """An uninformative Server header should be overridden by agreeing new signals."""
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
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<center>nginx</center>",
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            body_snippet="<center>nginx</center>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=error_pages,
        malformed_request_probes=malformed,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "medium"
    evidence_signals = {e["signal"] for e in ident["evidence"]}
    assert "server_header" not in evidence_signals
    assert "error_page_body" in evidence_signals
    assert "malformed_response_body" in evidence_signals


def test_malformed_server_header_merges_into_direct(monkeypatch) -> None:
    """Malformed response Server header should merge into direct votes."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            server_header="lighttpd/1.4.71",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "lighttpd"
    assert result.metadata["server_identification"]["confidence"] == "high"


def test_no_signals_at_all(monkeypatch) -> None:
    """No headers, no error page, no malformed response → unknown."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=[],
        malformed_request_probes=[],
    )

    assert result.server_type is None
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "none"


def test_only_weak_via_insufficient_for_classification(monkeypatch) -> None:
    """Via header alone (weak) should create evidence but not classify."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            via_header="1.1 nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=[],
        malformed_request_probes=[],
    )

    assert result.server_type is None
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "none"
    assert len(ident["evidence"]) == 1
    assert ident["evidence"][0]["signal"] == "via_header"


def test_error_page_and_malformed_body_agree_accumulate(monkeypatch) -> None:
    """Error page + malformed body both say apache → shares bucket, medium confidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="Apache Server at example.com Port 443",
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            body_snippet="Your browser sent a request that this server could not understand.",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=error_pages,
        malformed_request_probes=malformed,
    )

    assert result.server_type == "apache"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "medium"


def test_error_page_and_malformed_body_conflict(monkeypatch) -> None:
    """Error page says nginx, malformed body says apache → ambiguous in shared bucket."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<center>nginx</center>",
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            body_snippet="Apache Server at example.com Port 443",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=error_pages,
        malformed_request_probes=malformed,
    )

    ident = result.metadata["server_identification"]
    assert ident["ambiguous"] is True
    assert set(ident["candidate_server_types"]) == {"apache", "nginx"}
