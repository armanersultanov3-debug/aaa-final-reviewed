from tests.external_helpers import (
    ProbeAttempt,
    ProbeTarget,
    SensitivePathProbe,
    ServerIdentification,
    ServerIdentificationEvidence,
    analyze_external_target,
    pytest,
    run_external_rules,
    _ALL_SECURITY_HEADERS,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    _server_identification,
)

def test_probe_target_url_brackets_ipv6_host() -> None:
    target = ProbeTarget(scheme="http", host="2001:db8::1", port=8080, path="/")
    assert target.url == "http://[2001:db8::1]:8080/"


def test_probe_target_url_ipv4_not_bracketed() -> None:
    target = ProbeTarget(scheme="https", host="192.168.1.1", port=443, path="/")
    assert target.url == "https://192.168.1.1/"


def test_probe_target_url_hostname_not_bracketed() -> None:
    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")
    assert target.url == "https://example.com/"


def test_analyze_external_target_detects_nginx_server_type(monkeypatch) -> None:
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
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.mode == "external"
    assert result.target == "example.com"
    assert result.server_type == "nginx"
    assert result.findings == []
    assert result.issues == []
    assert "probable_server_type: nginx" in result.diagnostics
    assert result.metadata["probe_attempts"][0]["url"] == "https://example.com/"
    assert result.metadata["probe_attempts"][0]["strict_transport_security_header"] == "max-age=31536000; includeSubDomains"


def test_analyze_external_target_passes_server_identification_into_rules(monkeypatch) -> None:
    captured: dict[str, object] = {}
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
    attempts_by_target = {attempt.target: attempt for attempt in probe_attempts}

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
        lambda successful_attempts, identification=None: [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: [],
    )

    def fake_run_external_rules(
        attempts: list[ProbeAttempt],
        target: str,
        sensitive_path_probes: list[SensitivePathProbe] | None = None,
        server_identification: ServerIdentification | None = None,
    ):
        captured["attempts"] = attempts
        captured["target"] = target
        captured["sensitive_path_probes"] = sensitive_path_probes
        captured["server_identification"] = server_identification
        return []

    monkeypatch.setattr(
        "webconf_audit.external.recon.run_external_rules",
        fake_run_external_rules,
    )

    result = analyze_external_target("example.com")

    assert result.server_type == "nginx"
    assert captured["target"] == "example.com"
    assert captured["sensitive_path_probes"] == []
    identification = captured["server_identification"]
    assert isinstance(identification, ServerIdentification)
    assert identification.server_type == "nginx"
    assert identification.confidence == "high"


def test_run_external_rules_server_identification_is_noop_for_non_nginx_server() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="nginx/1.24.0"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="high",
        evidence=(),
        candidate_server_types=("apache",),
    )

    baseline = run_external_rules(probe_attempts, "example.com")
    with_identification = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    assert [f.rule_id for f in with_identification] == [f.rule_id for f in baseline]
    assert [f.location.target for f in with_identification] == [
        f.location.target for f in baseline
    ]


def test_nginx_conditional_version_rule_fires_at_high_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="nginx/1.24.0"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.nginx.version_disclosed_in_server_header" in rule_ids
    assert "external.server_version_disclosed" not in rule_ids


def test_nginx_conditional_version_rule_does_not_fire_below_threshold() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="nginx/1.24.0"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="low",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.nginx.version_disclosed_in_server_header" not in rule_ids
    assert "external.server_version_disclosed" in rule_ids


def test_nginx_conditional_version_rule_does_not_fire_for_other_server_type() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="nginx/1.24.0"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="high",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.nginx.version_disclosed_in_server_header" not in rule_ids
    assert "external.server_version_disclosed" in rule_ids


def test_nginx_default_welcome_page_rule_fires_at_medium_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx",
            body_snippet=(
                "<html><title>Welcome to nginx!</title>"
                "<body>Welcome to nginx! If you see this page, the nginx web "
                "server is successfully installed and working.</body></html>"
            ),
        ),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="medium",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    welcome_findings = [
        f for f in findings if f.rule_id == "external.nginx.default_welcome_page"
    ]
    assert len(welcome_findings) == 1
    assert welcome_findings[0].location.target == "https://example.com/"


def test_nginx_default_welcome_page_rule_does_not_fire_for_custom_page() -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx",
            body_snippet="<html><body>Custom application homepage</body></html>",
        ),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    assert "external.nginx.default_welcome_page" not in {f.rule_id for f in findings}


def test_nginx_default_welcome_page_rule_does_not_fire_for_non_root_path() -> None:
    probe_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(
                scheme="https",
                host="example.com",
                port=443,
                path="/app",
            ),
            server_header="nginx",
            body_snippet=(
                "Welcome to nginx! If you see this page, the nginx web server "
                "is successfully installed and working."
            ),
        ),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com/app",
        server_identification=identification,
    )

    assert "external.nginx.default_welcome_page" not in {f.rule_id for f in findings}


def test_apache_conditional_version_rule_fires_at_high_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58 (Ubuntu)"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="high",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.apache.version_disclosed_in_server_header" in rule_ids
    assert "external.server_version_disclosed" not in rule_ids


def test_apache_conditional_version_rule_does_not_fire_below_threshold() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58 (Ubuntu)"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="low",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.apache.version_disclosed_in_server_header" not in rule_ids
    assert "external.server_version_disclosed" in rule_ids


def test_apache_mod_status_public_fires_at_medium_confidence() -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status?auto",
            path="/server-status?auto",
            status_code=200,
            content_type="text/plain",
            body_snippet="Total Accesses: 1",
        )
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="medium",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Apache/2.4.58")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.apache.mod_status_public" in rule_ids
    assert "external.server_status_exposed" not in rule_ids


def test_apache_mod_status_public_does_not_fire_for_other_server_type() -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status",
            path="/server-status",
            status_code=200,
            content_type="text/html",
        )
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="nginx")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.apache.mod_status_public" not in rule_ids
    assert "external.server_status_exposed" in rule_ids


def test_apache_etag_inode_disclosure_fires_at_high_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="Apache/2.4.58",
            etag_header='"2c-5f5e100-61a1b2c3"',
        ),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="high",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    assert "external.apache.etag_inode_disclosure" in {f.rule_id for f in findings}


def test_apache_etag_inode_disclosure_does_not_fire_for_generic_etag() -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="Apache/2.4.58",
            etag_header='"abc123"',
        ),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="high",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    assert "external.apache.etag_inode_disclosure" not in {
        f.rule_id for f in findings
    }


def test_iis_aspnet_version_header_rule_fires_at_medium_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="iis",
        confidence="medium",
        evidence=(),
        candidate_server_types=("iis",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.iis.aspnet_version_header_present" in rule_ids
    assert "external.x_aspnet_version_header_present" not in rule_ids


def test_iis_aspnet_version_header_rule_does_not_fire_below_threshold() -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="iis",
        confidence="low",
        evidence=(),
        candidate_server_types=("iis",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.iis.aspnet_version_header_present" not in rule_ids
    assert "external.x_aspnet_version_header_present" in rule_ids


def test_iis_aspnet_version_header_rule_does_not_fire_for_other_server_type() -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.iis.aspnet_version_header_present" not in rule_ids
    assert "external.x_aspnet_version_header_present" in rule_ids


def test_iis_detailed_error_page_rule_fires_for_error_page_evidence() -> None:
    identification = ServerIdentification(
        server_type="iis",
        confidence="high",
        evidence=(
            ServerIdentificationEvidence(
                source_url="https://example.com/_wca_nonexistent_404_probe",
                signal="error_page_body",
                value="<h2>IIS Detailed Error - 404.0 - Not Found</h2>",
                indicates="iis",
                strength="moderate",
                detail="Default error page matches IIS detailed error content.",
            ),
        ),
        candidate_server_types=("iis",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Microsoft-IIS/10.0")],
        "example.com",
        server_identification=identification,
    )

    detailed_findings = [
        f for f in findings if f.rule_id == "external.iis.detailed_error_page"
    ]
    assert len(detailed_findings) == 1
    assert detailed_findings[0].location.target == "https://example.com/_wca_nonexistent_404_probe"


def test_iis_detailed_error_page_rule_fires_for_malformed_evidence() -> None:
    identification = ServerIdentification(
        server_type="iis",
        confidence="medium",
        evidence=(
            ServerIdentificationEvidence(
                source_url="https://example.com/",
                signal="malformed_response_body",
                value="<title>Server Error in '/' Application.</title>",
                indicates="iis",
                strength="moderate",
                detail="Malformed response matches IIS detailed error content.",
            ),
        ),
        candidate_server_types=("iis",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Microsoft-IIS/10.0")],
        "example.com",
        server_identification=identification,
    )

    assert "external.iis.detailed_error_page" in {f.rule_id for f in findings}


def test_iis_detailed_error_page_rule_does_not_fire_for_non_detailed_iis_evidence() -> None:
    identification = ServerIdentification(
        server_type="iis",
        confidence="high",
        evidence=(
            ServerIdentificationEvidence(
                source_url="https://example.com/",
                signal="malformed_response_body",
                value="<h2>Bad Request - Invalid URL</h2>",
                indicates="iis",
                strength="moderate",
                detail="Malformed response body matches a generic IIS signature.",
            ),
        ),
        candidate_server_types=("iis",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Microsoft-IIS/10.0")],
        "example.com",
        server_identification=identification,
    )

    assert "external.iis.detailed_error_page" not in {f.rule_id for f in findings}


def test_lighttpd_version_in_server_header_fires_at_high_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="lighttpd/1.4.71"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="lighttpd",
        confidence="high",
        evidence=(),
        candidate_server_types=("lighttpd",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.lighttpd.version_in_server_header" in rule_ids
    assert "external.server_version_disclosed" not in rule_ids


def test_lighttpd_version_in_server_header_does_not_fire_below_threshold() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="lighttpd/1.4.71"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="lighttpd",
        confidence="low",
        evidence=(),
        candidate_server_types=("lighttpd",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.lighttpd.version_in_server_header" not in rule_ids
    assert "external.server_version_disclosed" in rule_ids


def test_lighttpd_mod_status_public_fires_at_medium_confidence() -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status",
            path="/server-status",
            status_code=200,
            content_type="text/plain",
            body_snippet="Total Accesses: 1",
        )
    ]
    identification = ServerIdentification(
        server_type="lighttpd",
        confidence="medium",
        evidence=(),
        candidate_server_types=("lighttpd",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="lighttpd/1.4.71")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.lighttpd.mod_status_public" in rule_ids
    assert "external.server_status_exposed" not in rule_ids


def test_lighttpd_mod_status_public_does_not_fire_for_other_server_type() -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status",
            path="/server-status",
            status_code=200,
            content_type="text/plain",
            body_snippet="Total Accesses: 1",
        )
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="nginx")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.lighttpd.mod_status_public" not in rule_ids
    assert "external.server_status_exposed" in rule_ids


@pytest.mark.parametrize(
    ("confidence", "should_fire"),
    [
        ("medium", True),
        ("high", True),
        ("low", False),
        ("none", False),
    ],
)
def test_nginx_default_welcome_page_rule_threshold_behavior(
    confidence: str,
    should_fire: bool,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx",
            body_snippet=(
                "<html><title>Welcome to nginx!</title>"
                "<body>Welcome to nginx! If you see this page, the nginx web "
                "server is successfully installed and working.</body></html>"
            ),
        ),
        _http_redirect_probe(),
    ]
    identification = _server_identification(
        "nginx" if confidence != "none" else None,
        confidence,
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    assert ("external.nginx.default_welcome_page" in {f.rule_id for f in findings}) is should_fire


@pytest.mark.parametrize(
    ("confidence", "should_fire"),
    [
        ("medium", True),
        ("high", True),
        ("low", False),
        ("none", False),
    ],
)
def test_apache_mod_status_public_threshold_behavior(
    confidence: str,
    should_fire: bool,
) -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status?auto",
            path="/server-status?auto",
            status_code=200,
            content_type="text/plain",
            body_snippet="Total Accesses: 1",
        )
    ]
    identification = _server_identification(
        "apache" if confidence != "none" else None,
        confidence,
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Apache/2.4.58")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert ("external.apache.mod_status_public" in rule_ids) is should_fire
    assert ("external.server_status_exposed" in rule_ids) is (not should_fire)


@pytest.mark.parametrize(
    ("confidence", "should_fire"),
    [
        ("medium", True),
        ("high", True),
        ("low", False),
        ("none", False),
    ],
)
def test_iis_detailed_error_page_rule_threshold_behavior(
    confidence: str,
    should_fire: bool,
) -> None:
    identification = _server_identification(
        "iis" if confidence != "none" else None,
        confidence,
        evidence=(
            ServerIdentificationEvidence(
                source_url="https://example.com/",
                signal="malformed_response_body",
                value="<title>Server Error in '/' Application.</title>",
                indicates="iis",
                strength="moderate",
                detail="Malformed response matches IIS detailed error content.",
            ),
        ),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Microsoft-IIS/10.0")],
        "example.com",
        server_identification=identification,
    )

    assert ("external.iis.detailed_error_page" in {f.rule_id for f in findings}) is should_fire


def test_iis_detailed_error_page_rule_does_not_fire_for_other_server_type() -> None:
    identification = _server_identification(
        "apache",
        "high",
        evidence=(
            ServerIdentificationEvidence(
                source_url="https://example.com/",
                signal="malformed_response_body",
                value="<title>Server Error in '/' Application.</title>",
                indicates="iis",
                strength="moderate",
                detail="Malformed response matches IIS detailed error content.",
            ),
        ),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Apache/2.4.58")],
        "example.com",
        server_identification=identification,
    )

    assert "external.iis.detailed_error_page" not in {f.rule_id for f in findings}


@pytest.mark.parametrize(
    ("confidence", "should_fire"),
    [
        ("medium", True),
        ("high", True),
        ("low", False),
        ("none", False),
    ],
)
def test_lighttpd_mod_status_public_threshold_behavior(
    confidence: str,
    should_fire: bool,
) -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status",
            path="/server-status",
            status_code=200,
            content_type="text/plain",
            body_snippet="Total Accesses: 1",
        )
    ]
    identification = _server_identification(
        "lighttpd" if confidence != "none" else None,
        confidence,
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="lighttpd/1.4.71")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert ("external.lighttpd.mod_status_public" in rule_ids) is should_fire
    assert ("external.server_status_exposed" in rule_ids) is (not should_fire)


def test_analyze_external_target_returns_issue_when_no_service_is_reachable(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.mode == "external"
    assert result.server_type is None
    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "external_no_http_service"
    assert result.issues[0].location is not None
    assert result.issues[0].location.kind == "endpoint"


def test_analyze_external_target_returns_warning_when_server_type_is_unknown(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="custom-edge",
            **_ALL_SECURITY_HEADERS,
        )
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.mode == "external"
    assert result.server_type is None
    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "external_server_type_unknown"


def test_analyze_external_target_adds_https_not_available_finding_when_https_has_no_response(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=301,
            reason_phrase="Moved Permanently",
            server_header="apache/2.4.58",
            location_header="https://example.com/",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.https_not_available" in {finding.rule_id for finding in result.findings}


def test_analyze_external_target_adds_http_not_redirected_to_https_finding_when_http_returns_200(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            strict_transport_security_header="max-age=31536000",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.http_not_redirected_to_https" in {finding.rule_id for finding in result.findings}


def test_analyze_external_target_does_not_add_http_redirect_finding_for_https_redirect(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="apache/2.4.58",
            strict_transport_security_header="max-age=31536000",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=301,
            reason_phrase="Moved Permanently",
            server_header="apache/2.4.58",
            location_header="https://example.com/",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.http_not_redirected_to_https" not in {
        finding.rule_id for finding in result.findings
    }


def test_analyze_external_target_adds_hsts_missing_finding_for_https_without_header(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=301,
            reason_phrase="Moved Permanently",
            server_header="nginx/1.24.0",
            location_header="https://example.com/",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.hsts_header_missing" in {finding.rule_id for finding in result.findings}


def test_analyze_external_target_does_not_add_hsts_missing_finding_when_header_exists(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            strict_transport_security_header="max-age=31536000",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=301,
            reason_phrase="Moved Permanently",
            server_header="nginx/1.24.0",
            location_header="https://example.com/",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.hsts_header_missing" not in {finding.rule_id for finding in result.findings}


def test_analyze_external_target_returns_findings_in_analysis_result(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="apache/2.4.58",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "external.https_not_available" in rule_ids
    assert "external.http_not_redirected_to_https" in rule_ids
    assert "external.apache.version_disclosed_in_server_header" in rule_ids
    assert "external.server_version_disclosed" not in rule_ids
    assert all(finding.kind == "finding" for finding in result.findings)
