from tests.external_helpers import (
    ErrorPageProbe,
    MalformedRequestProbe,
    ProbeAttempt,
    ProbeTarget,
    SensitivePathProbe,
    ServerIdentification,
    analyze_external_target,
    pytest,
    _ALL_SECURITY_HEADERS,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    _sensitive_path_probe,
)

def test_sensitive_paths_phase_1_4_1_set() -> None:
    from webconf_audit.external.recon import _SENSITIVE_PATHS
    from webconf_audit.external.safe_probe_catalog import DEFAULT_SAFE_PROBE_PATHS

    assert _SENSITIVE_PATHS == DEFAULT_SAFE_PROBE_PATHS == (
        "/.git/HEAD",
        "/server-status",
        "/server-info",
        "/nginx_status",
        "/.env",
        "/.htaccess",
        "/.htpasswd",
        "/wp-admin/",
        "/phpinfo.php",
        "/elmah.axd",
        "/trace.axd",
        "/web.config",
        "/robots.txt",
        "/sitemap.xml",
        "/.svn/entries",
        "/backup.zip",
        "/backup.tar.gz",
        "/site.zip",
        "/www.zip",
        "/backup.sql",
        "/db.sql",
        "/dump.sql",
        "/composer.json",
        "/composer.lock",
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/.npmrc",
    )


def test_safe_probe_catalog_is_limited_to_safe_methods() -> None:
    from webconf_audit.external.safe_probe_catalog import (
        CONDITIONAL_SAFE_PATH_PROBES,
        SAFE_PATH_RULES,
    )

    allowed_methods = {"GET", "HEAD", "OPTIONS"}
    assert {rule.method for rule in SAFE_PATH_RULES} <= allowed_methods
    assert {probe.method for probe in CONDITIONAL_SAFE_PATH_PROBES} <= allowed_methods


def test_conditional_safe_probe_paths_are_grouped_by_server_type() -> None:
    from webconf_audit.external.safe_probe_catalog import (
        ConditionalSafePathProbe,
        _conditional_safe_probe_paths_by_server_type,
    )

    grouped_paths = _conditional_safe_probe_paths_by_server_type(
        (
            ConditionalSafePathProbe(path="/server-status?auto", server_type="apache"),
            ConditionalSafePathProbe(path="/server-status", server_type="apache"),
            ConditionalSafePathProbe(path="/nginx_status", server_type="nginx"),
        )
    )

    assert grouped_paths == {
        "apache": ("/server-status?auto", "/server-status"),
        "nginx": ("/nginx_status",),
    }


def test_conditional_safe_probe_paths_honor_minimum_confidences() -> None:
    from webconf_audit.external.safe_probe_catalog import (
        ConditionalSafePathProbe,
        _conditional_safe_probe_paths_by_server_type,
    )

    probes = (
        ConditionalSafePathProbe(
            path="/server-status?auto",
            server_type="apache",
            minimum_confidences=frozenset({"medium", "high"}),
        ),
        ConditionalSafePathProbe(
            path="/server-status-high",
            server_type="apache",
            minimum_confidences=frozenset({"high"}),
        ),
        ConditionalSafePathProbe(
            path="/nginx_status",
            server_type="nginx",
            minimum_confidences=frozenset({"medium", "high"}),
        ),
    )

    assert _conditional_safe_probe_paths_by_server_type(probes, "medium") == {
        "apache": ("/server-status?auto",),
        "nginx": ("/nginx_status",),
    }
    assert _conditional_safe_probe_paths_by_server_type(probes, "high") == {
        "apache": ("/server-status?auto", "/server-status-high"),
        "nginx": ("/nginx_status",),
    }


def test_safe_probe_catalog_default_paths_are_explicit_and_unique() -> None:
    from webconf_audit.external.safe_probe_catalog import (
        DEFAULT_SAFE_PROBE_PATHS,
        SAFE_PATH_RULES,
    )

    default_paths = [
        path for rule in SAFE_PATH_RULES for path in (rule.default_paths or rule.paths)
    ]

    assert tuple(default_paths) == DEFAULT_SAFE_PROBE_PATHS
    assert len(default_paths) == len(set(default_paths))
    assert all(path in rule.paths for rule in SAFE_PATH_RULES for path in rule.default_paths)


def test_safe_probe_catalog_registers_sensitive_rule_metadata() -> None:
    from webconf_audit.external.safe_probe_catalog import SAFE_PATH_RULES
    from webconf_audit.rule_registry import registry

    for rule in SAFE_PATH_RULES:
        meta = registry.get_meta(rule.rule_id)
        assert meta is not None
        assert meta.title == rule.title
        assert meta.severity == rule.severity
        assert meta.description == rule.description
        assert meta.order == rule.order
        assert meta.recommendation == (
            rule.metadata_recommendation or rule.recommendation
        )


def test_probe_sensitive_paths_uses_all_universal_paths(monkeypatch) -> None:
    from webconf_audit.external.recon import _SENSITIVE_PATHS, _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    _probe_sensitive_paths([_https_probe_with_headers()])

    assert seen_paths == list(_SENSITIVE_PATHS)


def test_probe_sensitive_paths_deduplicates_same_endpoint(monkeypatch) -> None:
    from webconf_audit.external.recon import _SENSITIVE_PATHS, _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    duplicate_attempts = [_https_probe_with_headers(), _https_probe_with_headers()]
    _probe_sensitive_paths(duplicate_attempts)

    assert seen_paths == list(_SENSITIVE_PATHS)


@pytest.mark.parametrize("confidence", ["medium", "high"])
def test_probe_sensitive_paths_adds_apache_conditional_paths_at_supported_confidence(
    monkeypatch,
    confidence: str,
) -> None:
    from webconf_audit.external.recon import _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    identification = ServerIdentification(
        server_type="apache",
        confidence=confidence,
        evidence=(),
        candidate_server_types=("apache",),
    )
    _probe_sensitive_paths([_https_probe_with_headers()], identification)

    assert "/server-status?auto" in seen_paths


def test_probe_sensitive_paths_skips_conditional_paths_for_unknown_identification(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    identification = ServerIdentification(
        server_type=None,
        confidence="none",
        evidence=(),
    )
    _probe_sensitive_paths([_https_probe_with_headers()], identification)

    assert "/server-status?auto" not in seen_paths


def test_probe_sensitive_paths_skips_conditional_paths_for_ambiguous_identification(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    identification = ServerIdentification(
        server_type=None,
        confidence="none",
        evidence=(),
        ambiguous=True,
        candidate_server_types=("apache", "nginx"),
    )
    _probe_sensitive_paths([_https_probe_with_headers()], identification)

    assert "/server-status?auto" not in seen_paths


def test_probe_sensitive_paths_skips_conditional_paths_for_other_server_type(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )
    _probe_sensitive_paths([_https_probe_with_headers()], identification)

    assert "/server-status?auto" not in seen_paths


def test_probe_sensitive_paths_skips_conditional_paths_for_low_confidence(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    identification = ServerIdentification(
        server_type="apache",
        confidence="low",
        evidence=(),
        candidate_server_types=("apache",),
    )
    _probe_sensitive_paths([_https_probe_with_headers()], identification)

    assert "/server-status?auto" not in seen_paths


def test_analyze_external_target_wires_identification_into_conditional_sensitive_paths(
    monkeypatch,
) -> None:
    seen_paths: list[str] = []
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58",
            **_ALL_SECURITY_HEADERS,
        )
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
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: [],
    )

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    result = analyze_external_target("example.com")

    assert result.server_type == "apache"
    assert "/server-status?auto" in seen_paths


def test_analyze_external_target_adds_conditional_sensitive_path_at_medium_confidence(
    monkeypatch,
) -> None:
    seen_paths: list[str] = []
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
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: [
            ErrorPageProbe(
                url="https://example.com/_wca_nonexistent_404_probe",
                status_code=404,
                body_snippet="Apache Server at example.com Port 443",
            )
        ],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: [
            MalformedRequestProbe(
                url="https://example.com/",
                status_code=400,
                body_snippet="Apache Server at example.com Port 443",
            )
        ],
    )

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    result = analyze_external_target("example.com")

    assert result.server_type == "apache"
    assert result.metadata["server_identification"]["confidence"] == "medium"
    assert "/server-status?auto" in seen_paths
    assert any(
        probe["path"] == "/server-status?auto"
        for probe in result.metadata["sensitive_path_probes"]
    )


def test_analyze_external_target_skips_conditional_sensitive_path_when_unknown(
    monkeypatch,
) -> None:
    seen_paths: list[str] = []
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
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: [],
    )

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    result = analyze_external_target("example.com")

    assert result.server_type is None
    assert "/server-status?auto" not in seen_paths
    assert all(
        probe["path"] != "/server-status?auto"
        for probe in result.metadata["sensitive_path_probes"]
    )


def test_sensitive_path_probes_in_metadata(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/.git/HEAD",
        path="/.git/HEAD",
        status_code=200,
        content_type="text/plain",
        body_snippet="ref: refs/heads/main",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    meta_sp = result.metadata["sensitive_path_probes"]
    assert len(meta_sp) == 1
    assert meta_sp[0]["url"] == "https://example.com/.git/HEAD"
    assert meta_sp[0]["path"] == "/.git/HEAD"
    assert meta_sp[0]["status_code"] == 200
    assert meta_sp[0]["content_type"] == "text/plain"
    assert meta_sp[0]["body_snippet"] == "ref: refs/heads/main"
    assert meta_sp[0]["error_message"] is None


def test_sensitive_path_probes_empty_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["sensitive_path_probes"] == []


# ---------------------------------------------------------------------------
# external.git_metadata_exposed
# ---------------------------------------------------------------------------


def test_git_metadata_exposed_fires_on_ref_body(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/.git/HEAD",
        path="/.git/HEAD",
        status_code=200,
        content_type="text/plain",
        body_snippet="ref: refs/heads/main",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    findings = [f for f in result.findings if f.rule_id == "external.git_metadata_exposed"]
    assert len(findings) == 1
    assert findings[0].location.target == "https://example.com/.git/HEAD"
    assert findings[0].location.details == "/.git/HEAD"


def test_git_metadata_exposed_does_not_fire_on_404(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/.git/HEAD",
        path="/.git/HEAD",
        status_code=404,
        content_type="text/html",
        body_snippet="Not Found",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    assert "external.git_metadata_exposed" not in {f.rule_id for f in result.findings}


def test_git_metadata_exposed_does_not_fire_without_ref_body(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/.git/HEAD",
        path="/.git/HEAD",
        status_code=200,
        content_type="text/html",
        body_snippet="<html>Custom 200 page</html>",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    assert "external.git_metadata_exposed" not in {f.rule_id for f in result.findings}


def test_git_metadata_exposed_does_not_fire_when_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.git_metadata_exposed" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# external.server_status_exposed
# ---------------------------------------------------------------------------


def test_server_status_exposed_fires_on_200(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-status",
        path="/server-status",
        status_code=200,
        content_type="text/html",
        body_snippet="<html>Apache Status</html>",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    findings = [f for f in result.findings if f.rule_id == "external.server_status_exposed"]
    assert len(findings) == 1
    assert findings[0].location.target == "https://example.com/server-status"


def test_server_status_exposed_fires_on_server_status_auto(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-status?auto",
        path="/server-status?auto",
        status_code=200,
        content_type="text/plain",
        body_snippet="Total Accesses: 1",
    )
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=[sp],
    )
    findings = [f for f in result.findings if f.rule_id == "external.server_status_exposed"]
    assert len(findings) == 1
    assert findings[0].location.target == "https://example.com/server-status?auto"
    assert findings[0].location.details == "/server-status?auto"


def test_server_status_exposed_does_not_fire_on_403(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-status",
        path="/server-status",
        status_code=403,
        content_type="text/html",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    assert "external.server_status_exposed" not in {f.rule_id for f in result.findings}


def test_server_status_exposed_does_not_fire_on_server_status_auto_404(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-status?auto",
        path="/server-status?auto",
        status_code=404,
        content_type="text/plain",
    )
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=[sp],
    )
    assert "external.server_status_exposed" not in {f.rule_id for f in result.findings}


def test_server_status_exposed_does_not_fire_when_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.server_status_exposed" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# external.server_info_exposed
# ---------------------------------------------------------------------------


def test_server_info_exposed_fires_on_200(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-info",
        path="/server-info",
        status_code=200,
        content_type="text/html",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    findings = [f for f in result.findings if f.rule_id == "external.server_info_exposed"]
    assert len(findings) == 1
    assert findings[0].location.target == "https://example.com/server-info"


def test_server_info_exposed_does_not_fire_on_404(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-info",
        path="/server-info",
        status_code=404,
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    assert "external.server_info_exposed" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# external.nginx_status_exposed
# ---------------------------------------------------------------------------


def test_nginx_status_exposed_fires_on_200(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/nginx_status",
        path="/nginx_status",
        status_code=200,
        content_type="text/plain",
        body_snippet="Active connections: 1",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    findings = [f for f in result.findings if f.rule_id == "external.nginx_status_exposed"]
    assert len(findings) == 1
    assert findings[0].location.target == "https://example.com/nginx_status"


def test_nginx_status_exposed_does_not_fire_on_404(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/nginx_status",
        path="/nginx_status",
        status_code=404,
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    assert "external.nginx_status_exposed" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# Expanded universal sensitive path rules (Phase 1.4.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "rule_id", "content_type", "body_snippet"),
    [
        ("/.env", "external.env_file_exposed", "text/plain", "SECRET_KEY=abc123\nAPP_ENV=prod"),
        ("/.htaccess", "external.htaccess_exposed", "text/plain", "Deny from all"),
        ("/.htpasswd", "external.htpasswd_exposed", "text/plain", "admin:$apr1$example"),
        (
            "/wp-admin/",
            "external.wordpress_admin_panel_exposed",
            "text/html",
            "<title>Log In - WordPress</title>",
        ),
        (
            "/phpinfo.php",
            "external.phpinfo_exposed",
            "text/html",
            "<title>phpinfo()</title>",
        ),
        (
            "/elmah.axd",
            "external.elmah_axd_exposed",
            "text/html",
            "<html>Error Log for Application</html>",
        ),
        (
            "/trace.axd",
            "external.trace_axd_exposed",
            "text/html",
            "<html>Application Trace</html>",
        ),
        (
            "/web.config",
            "external.web_config_exposed",
            "application/xml",
            "<configuration><appSettings /></configuration>",
        ),
        ("/robots.txt", "external.robots_txt_exposed", "text/plain", "User-agent: *"),
        (
            "/sitemap.xml",
            "external.sitemap_xml_exposed",
            "application/xml",
            "<?xml version='1.0'?><urlset />",
        ),
        ("/.svn/entries", "external.svn_metadata_exposed", "text/plain", "12\n"),
    ],
)
def test_expanded_sensitive_path_rules_fire_on_accessible_match(
    monkeypatch,
    path: str,
    rule_id: str,
    content_type: str,
    body_snippet: str,
) -> None:
    sp = _sensitive_path_probe(
        path,
        status_code=200,
        content_type=content_type,
        body_snippet=body_snippet,
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=[sp],
    )

    findings = [f for f in result.findings if f.rule_id == rule_id]
    assert len(findings) == 1
    assert findings[0].location.target == f"https://example.com{path}"
    assert findings[0].location.details == path


@pytest.mark.parametrize(
    ("path", "rule_id"),
    [
        ("/.env", "external.env_file_exposed"),
        ("/.htaccess", "external.htaccess_exposed"),
        ("/.htpasswd", "external.htpasswd_exposed"),
        ("/wp-admin/", "external.wordpress_admin_panel_exposed"),
        ("/phpinfo.php", "external.phpinfo_exposed"),
        ("/elmah.axd", "external.elmah_axd_exposed"),
        ("/trace.axd", "external.trace_axd_exposed"),
        ("/web.config", "external.web_config_exposed"),
        ("/robots.txt", "external.robots_txt_exposed"),
        ("/sitemap.xml", "external.sitemap_xml_exposed"),
        ("/.svn/entries", "external.svn_metadata_exposed"),
    ],
)
def test_expanded_sensitive_path_rules_do_not_fire_on_404(
    monkeypatch,
    path: str,
    rule_id: str,
) -> None:
    sp = _sensitive_path_probe(path, status_code=404, body_snippet="Not Found")
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=[sp],
    )

    assert rule_id not in {f.rule_id for f in result.findings}


@pytest.mark.parametrize(
    ("path", "rule_id", "body_snippet"),
    [
        ("/.env", "external.env_file_exposed", "<html>Custom page</html>"),
        ("/phpinfo.php", "external.phpinfo_exposed", "<html>PHP status</html>"),
        ("/web.config", "external.web_config_exposed", "<html>configuration</html>"),
        ("/backup.zip", "external.backup_archive_exposed", "<html>Custom page</html>"),
    ],
)
def test_body_matched_sensitive_path_rules_require_expected_content(
    monkeypatch,
    path: str,
    rule_id: str,
    body_snippet: str,
) -> None:
    sp = _sensitive_path_probe(path, status_code=200, body_snippet=body_snippet)
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=[sp],
    )

    assert rule_id not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# No false positives from sensitive path rules on baseline probes
# ---------------------------------------------------------------------------


def test_no_sensitive_path_findings_on_baseline_probe(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    sensitive_rule_ids = {
        "external.git_metadata_exposed",
        "external.server_status_exposed",
        "external.server_info_exposed",
        "external.nginx_status_exposed",
        "external.env_file_exposed",
        "external.htaccess_exposed",
        "external.htpasswd_exposed",
        "external.wordpress_admin_panel_exposed",
        "external.phpinfo_exposed",
        "external.elmah_axd_exposed",
        "external.trace_axd_exposed",
        "external.web_config_exposed",
        "external.robots_txt_exposed",
        "external.sitemap_xml_exposed",
        "external.svn_metadata_exposed",
        "external.backup_archive_exposed",
        "external.database_dump_exposed",
        "external.dependency_manifest_exposed",
        "external.npmrc_exposed",
    }
    fired = sensitive_rule_ids & {f.rule_id for f in result.findings}
    assert fired == set()


def test_non_200_responses_do_not_trigger_sensitive_path_rules(monkeypatch) -> None:
    path_probes = [
        SensitivePathProbe(url="https://example.com/.git/HEAD", path="/.git/HEAD", status_code=404),
        SensitivePathProbe(url="https://example.com/server-status", path="/server-status", status_code=403),
        SensitivePathProbe(url="https://example.com/server-info", path="/server-info", status_code=500),
        SensitivePathProbe(url="https://example.com/nginx_status", path="/nginx_status", status_code=301),
        SensitivePathProbe(url="https://example.com/.env", path="/.env", status_code=404),
        SensitivePathProbe(url="https://example.com/.htaccess", path="/.htaccess", status_code=403),
        SensitivePathProbe(url="https://example.com/.htpasswd", path="/.htpasswd", status_code=404),
        SensitivePathProbe(url="https://example.com/wp-admin/", path="/wp-admin/", status_code=302),
        SensitivePathProbe(url="https://example.com/phpinfo.php", path="/phpinfo.php", status_code=404),
        SensitivePathProbe(url="https://example.com/elmah.axd", path="/elmah.axd", status_code=401),
        SensitivePathProbe(url="https://example.com/trace.axd", path="/trace.axd", status_code=403),
        SensitivePathProbe(url="https://example.com/web.config", path="/web.config", status_code=404),
        SensitivePathProbe(url="https://example.com/robots.txt", path="/robots.txt", status_code=304),
        SensitivePathProbe(url="https://example.com/sitemap.xml", path="/sitemap.xml", status_code=500),
        SensitivePathProbe(url="https://example.com/.svn/entries", path="/.svn/entries", status_code=404),
        SensitivePathProbe(url="https://example.com/backup.zip", path="/backup.zip", status_code=404),
        SensitivePathProbe(url="https://example.com/dump.sql", path="/dump.sql", status_code=403),
        SensitivePathProbe(url="https://example.com/package.json", path="/package.json", status_code=500),
        SensitivePathProbe(url="https://example.com/.npmrc", path="/.npmrc", status_code=404),
    ]
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=path_probes)
    sensitive_rule_ids = {
        "external.git_metadata_exposed",
        "external.server_status_exposed",
        "external.server_info_exposed",
        "external.nginx_status_exposed",
        "external.env_file_exposed",
        "external.htaccess_exposed",
        "external.htpasswd_exposed",
        "external.wordpress_admin_panel_exposed",
        "external.phpinfo_exposed",
        "external.elmah_axd_exposed",
        "external.trace_axd_exposed",
        "external.web_config_exposed",
        "external.robots_txt_exposed",
        "external.sitemap_xml_exposed",
        "external.svn_metadata_exposed",
        "external.backup_archive_exposed",
        "external.database_dump_exposed",
        "external.dependency_manifest_exposed",
        "external.npmrc_exposed",
    }
    fired = sensitive_rule_ids & {f.rule_id for f in result.findings}
    assert fired == set()


# ---------------------------------------------------------------------------
# Server identification evidence tests
# ---------------------------------------------------------------------------
