import hashlib

from tests.external_helpers import (
    ProbeAttempt,
    ProbeTarget,
    http,
    pytest,
    _ALL_SECURITY_HEADERS,
    _analyze_with_probe_attempts,
    _http_probe_with_headers,
    _http_redirect_probe,
    _https_probe_with_headers,
    _setup_head_fallback_probe,
)

def test_redirect_chain_metadata_and_diagnostics_present(monkeypatch) -> None:
    initial_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(location_header="https://example.com/start"),
    ]
    additional_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/start"),
            status_code=302,
            reason_phrase="Found",
            location_header="https://example.com/login",
        ),
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/login"),
        ),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        initial_attempts,
        additional_probe_attempts=additional_attempts,
    )

    chains = result.metadata["redirect_chains"]
    assert len(chains) == 1
    chain = chains[0]
    assert chain["source_url"] == "http://example.com/"
    assert chain["final_url"] == "https://example.com/login"
    assert [hop["url"] for hop in chain["hops"]] == [
        "http://example.com/",
        "https://example.com/start",
        "https://example.com/login",
    ]
    assert chain["loop_detected"] is False
    assert chain["mixed_scheme_redirect"] is False
    assert chain["cross_domain_redirect"] is False
    assert any(
        "redirect_chain: http://example.com/ -> https://example.com/start -> https://example.com/login"
        in diagnostic
        for diagnostic in result.diagnostics
    )


def test_redirect_chain_detects_mixed_scheme(monkeypatch) -> None:
    initial_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(location_header="https://example.com/start"),
    ]
    additional_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/start"),
            status_code=302,
            reason_phrase="Found",
            location_header="http://example.com/final",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/final"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
        ),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        initial_attempts,
        additional_probe_attempts=additional_attempts,
    )

    chain = result.metadata["redirect_chains"][0]
    assert chain["mixed_scheme_redirect"] is True
    assert chain["cross_domain_redirect"] is False
    assert any("redirect_chain_mixed_scheme:" in diagnostic for diagnostic in result.diagnostics)


def test_redirect_chain_detects_cross_domain_redirect(monkeypatch) -> None:
    initial_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(location_header="https://login.example.net/"),
    ]
    additional_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="login.example.net", port=443, path="/"),
            server_header="nginx",
        ),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        initial_attempts,
        additional_probe_attempts=additional_attempts,
    )

    chain = result.metadata["redirect_chains"][0]
    assert chain["cross_domain_redirect"] is True
    assert chain["final_url"] == "https://login.example.net/"
    assert any("redirect_chain_cross_domain:" in diagnostic for diagnostic in result.diagnostics)


def test_redirect_chain_detects_loop(monkeypatch) -> None:
    initial_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(location_header="https://example.com/start"),
    ]
    additional_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/start"),
            status_code=302,
            reason_phrase="Found",
            location_header="http://example.com/",
        ),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        initial_attempts,
        additional_probe_attempts=additional_attempts,
    )

    chain = result.metadata["redirect_chains"][0]
    assert chain["loop_detected"] is True
    assert chain["final_url"] == "http://example.com/"
    assert any("redirect_chain_loop:" in diagnostic for diagnostic in result.diagnostics)


def test_x_frame_options_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_missing" in {f.rule_id for f in result.findings}


def test_x_frame_options_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_missing" not in {f.rule_id for f in result.findings}


def test_x_content_type_options_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_content_type_options_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_content_type_options_missing" in {f.rule_id for f in result.findings}


def test_x_content_type_options_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_content_type_options_missing" not in {f.rule_id for f in result.findings}


def test_content_security_policy_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(content_security_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_missing" in {f.rule_id for f in result.findings}


def test_content_security_policy_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_missing" not in {f.rule_id for f in result.findings}


def test_content_security_policy_missing_frame_ancestors_fires_when_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(content_security_policy_header="default-src 'self'"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_missing_frame_ancestors" in rule_ids
    finding = next(
        f
        for f in result.findings
        if f.rule_id == "external.content_security_policy_missing_frame_ancestors"
    )
    assert finding.severity == "low"
    assert finding.location.details is not None
    assert "Content-Security-Policy:" in finding.location.details


def test_content_security_policy_frame_ancestors_does_not_fire_on_http(
    monkeypatch,
) -> None:
    probe_attempts = [
        _http_probe_with_headers(content_security_policy_header="default-src 'self'"),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_missing_frame_ancestors" not in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_frame_ancestors_does_not_fire_when_present(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header="default-src 'self'; Frame-Ancestors 'none'"
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_missing_frame_ancestors" not in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_empty_frame_ancestors_still_fires(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header="default-src 'self'; frame-ancestors;"
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_missing_frame_ancestors" in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_missing_does_not_also_fire_frame_ancestors(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(content_security_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_missing" in {f.rule_id for f in result.findings}
    assert "external.content_security_policy_missing_frame_ancestors" not in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_object_src_not_none_fires_when_not_restricted(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header=(
                "default-src 'self'; frame-ancestors 'self'; base-uri 'none'"
            )
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_object_src_not_none" in rule_ids
    finding = next(
        f
        for f in result.findings
        if f.rule_id == "external.content_security_policy_object_src_not_none"
    )
    assert finding.severity == "low"
    assert finding.location.details is not None
    assert "Content-Security-Policy:" in finding.location.details


def test_content_security_policy_object_src_not_none_accepts_explicit_none(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header=(
                "default-src 'self'; frame-ancestors 'self'; "
                "object-src 'none'; base-uri 'none'"
            )
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_object_src_not_none" not in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_object_src_not_none_accepts_default_src_none(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header=(
                "default-src 'none'; frame-ancestors 'self'; base-uri 'none'"
            )
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_object_src_not_none" not in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_empty_object_src_still_fires(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header=(
                "default-src 'none'; frame-ancestors 'self'; object-src; base-uri 'none'"
            )
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_object_src_not_none" in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_object_src_not_none_does_not_fire_on_http(
    monkeypatch,
) -> None:
    probe_attempts = [
        _http_probe_with_headers(
            content_security_policy_header=(
                "default-src 'self'; frame-ancestors 'self'; base-uri 'none'"
            )
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_object_src_not_none" not in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_base_uri_not_restricted_fires_when_missing(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header=(
                "default-src 'self'; frame-ancestors 'self'; object-src 'none'"
            )
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_base_uri_not_restricted" in rule_ids
    finding = next(
        f
        for f in result.findings
        if f.rule_id == "external.content_security_policy_base_uri_not_restricted"
    )
    assert finding.severity == "low"
    assert finding.location.details is not None
    assert "Content-Security-Policy:" in finding.location.details


def test_content_security_policy_base_uri_not_restricted_accepts_none(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header=(
                "default-src 'self'; frame-ancestors 'self'; "
                "object-src 'none'; base-uri 'none'"
            )
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_base_uri_not_restricted" not in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_base_uri_not_restricted_accepts_self(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header=(
                "default-src 'self'; frame-ancestors 'self'; "
                "object-src 'none'; base-uri 'self'"
            )
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_base_uri_not_restricted" not in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_empty_base_uri_still_fires(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header=(
                "default-src 'self'; frame-ancestors 'self'; "
                "object-src 'none'; base-uri;"
            )
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_base_uri_not_restricted" in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_base_uri_not_restricted_does_not_fire_on_http(
    monkeypatch,
) -> None:
    probe_attempts = [
        _http_probe_with_headers(
            content_security_policy_header=(
                "default-src 'self'; frame-ancestors 'self'; object-src 'none'"
            )
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_base_uri_not_restricted" not in {
        f.rule_id for f in result.findings
    }


def test_content_security_policy_missing_does_not_fire_minimum_quality_rules(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(content_security_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_missing" in rule_ids
    assert "external.content_security_policy_object_src_not_none" not in rule_ids
    assert "external.content_security_policy_base_uri_not_restricted" not in rule_ids


def test_content_security_policy_nonce_reused_fires(monkeypatch) -> None:
    shared_nonce = "'nonce-static123'"
    nonce_fingerprint = hashlib.sha256(shared_nonce.encode("utf-8")).hexdigest()[:12]
    probe_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            content_security_policy_header=(
                f"default-src 'self'; script-src 'self' {shared_nonce}"
            ),
        ),
        _https_probe_with_headers(
            target=ProbeTarget(
                scheme="https",
                host="example.com",
                port=443,
                path="/account",
            ),
            content_security_policy_header=(
                f"default-src 'self'; script-src 'self' {shared_nonce}"
            ),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "external.content_security_policy_nonce_reused"
    ]
    assert len(findings) == 1
    assert shared_nonce not in findings[0].description
    assert f"sha256:{nonce_fingerprint}" in findings[0].description
    assert findings[0].location.details is not None
    assert shared_nonce not in findings[0].location.details
    assert f"sha256:{nonce_fingerprint}" in findings[0].location.details
    assert "/account" in findings[0].location.details


def test_content_security_policy_nonce_reused_fires_for_default_src_fallback(
    monkeypatch,
) -> None:
    shared_nonce = "'nonce-default123'"
    nonce_fingerprint = hashlib.sha256(shared_nonce.encode("utf-8")).hexdigest()[:12]
    probe_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            content_security_policy_header=(
                f"default-src 'self' {shared_nonce}; object-src 'none'"
            ),
        ),
        _https_probe_with_headers(
            target=ProbeTarget(
                scheme="https",
                host="example.com",
                port=443,
                path="/account",
            ),
            content_security_policy_header=(
                f"default-src 'self' {shared_nonce}; object-src 'none'"
            ),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "external.content_security_policy_nonce_reused"
    ]
    assert len(findings) == 1
    assert shared_nonce not in findings[0].description
    assert f"sha256:{nonce_fingerprint}" in findings[0].description


def test_content_security_policy_nonce_reused_does_not_use_default_src_when_explicit_script_and_style_src_present(
    monkeypatch,
) -> None:
    shared_nonce = "'nonce-default123'"
    probe_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            content_security_policy_header=(
                f"default-src 'self' {shared_nonce}; "
                "script-src 'self'; style-src 'self'; object-src 'none'"
            ),
        ),
        _https_probe_with_headers(
            target=ProbeTarget(
                scheme="https",
                host="example.com",
                port=443,
                path="/account",
            ),
            content_security_policy_header=(
                f"default-src 'self' {shared_nonce}; "
                "script-src 'self'; style-src 'self'; object-src 'none'"
            ),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.content_security_policy_nonce_reused" not in {
        finding.rule_id for finding in result.findings
    }


def test_content_security_policy_nonce_reused_findings_are_stably_sorted(
    monkeypatch,
) -> None:
    first_nonce = "'nonce-alpha123'"
    second_nonce = "'nonce-zulu789'"
    probe_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            content_security_policy_header=(
                f"default-src 'self'; script-src 'self' {second_nonce} {first_nonce}"
            ),
        ),
        _https_probe_with_headers(
            target=ProbeTarget(
                scheme="https",
                host="example.com",
                port=443,
                path="/account",
            ),
            content_security_policy_header=(
                f"default-src 'self'; script-src 'self' {second_nonce} {first_nonce}"
            ),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "external.content_security_policy_nonce_reused"
    ]
    expected_fingerprints = sorted(
        hashlib.sha256(nonce.encode("utf-8")).hexdigest()[:12]
        for nonce in (first_nonce, second_nonce)
    )

    assert len(findings) == 2
    assert [
        finding.description.split("sha256:")[1].split(")")[0]
        for finding in findings
    ] == expected_fingerprints


def test_content_security_policy_nonce_reused_does_not_fire_for_distinct_nonces(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            content_security_policy_header=(
                "default-src 'self'; script-src 'self' 'nonce-first123'"
            ),
        ),
        _https_probe_with_headers(
            target=ProbeTarget(
                scheme="https",
                host="example.com",
                port=443,
                path="/account",
            ),
            content_security_policy_header=(
                "default-src 'self'; script-src 'self' 'nonce-second456'"
            ),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.content_security_policy_nonce_reused" not in {
        finding.rule_id for finding in result.findings
    }


def test_content_security_policy_nonce_reused_does_not_fire_for_hash_policy(
    monkeypatch,
) -> None:
    hash_policy = (
        "default-src 'self'; script-src 'self' "
        "'sha256-Z3VhcmQtbWUtd2l0aC1hLWhhc2g='"
    )
    probe_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            content_security_policy_header=hash_policy,
        ),
        _https_probe_with_headers(
            target=ProbeTarget(
                scheme="https",
                host="example.com",
                port=443,
                path="/account",
            ),
            content_security_policy_header=hash_policy,
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.content_security_policy_nonce_reused" not in {
        finding.rule_id for finding in result.findings
    }


def test_referrer_policy_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(referrer_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_missing" in {f.rule_id for f in result.findings}


def test_referrer_policy_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_missing" not in {f.rule_id for f in result.findings}


def test_permissions_policy_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(permissions_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.permissions_policy_missing" in {f.rule_id for f in result.findings}


def test_permissions_policy_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.permissions_policy_missing" not in {f.rule_id for f in result.findings}


def test_coep_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(cross_origin_embedder_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.coep_missing" in {f.rule_id for f in result.findings}


def test_coep_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.coep_missing" not in {f.rule_id for f in result.findings}


def test_coop_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(cross_origin_opener_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.coop_missing" in {f.rule_id for f in result.findings}


def test_coop_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.coop_missing" not in {f.rule_id for f in result.findings}


def test_corp_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(cross_origin_resource_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.corp_missing" in {f.rule_id for f in result.findings}


def test_corp_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.corp_missing" not in {f.rule_id for f in result.findings}


def test_server_version_disclosed_fires_when_version_in_header(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58 (Ubuntu)"),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    version_findings = [
        f for f in result.findings
        if f.rule_id == "external.apache.version_disclosed_in_server_header"
    ]
    assert len(version_findings) >= 1
    assert "Apache/2.4.58 (Ubuntu)" in version_findings[0].description


def test_server_version_disclosed_does_not_fire_for_minimal_header(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(server_header="nginx"), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.server_version_disclosed" not in {f.rule_id for f in result.findings}


def test_server_version_disclosed_does_not_fire_when_no_server_header(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.server_version_disclosed" not in {f.rule_id for f in result.findings}


# --- HSTS header invalid ---


def test_hsts_invalid_does_not_fire_for_valid_max_age(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header="max-age=31536000"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.hsts_header_invalid" not in {f.rule_id for f in result.findings}


def test_hsts_invalid_fires_when_max_age_missing(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header="includeSubDomains"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.hsts_header_invalid" in {f.rule_id for f in result.findings}


def test_hsts_invalid_fires_when_max_age_not_a_number(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header="max-age=abc"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.hsts_header_invalid" in {f.rule_id for f in result.findings}


def test_hsts_invalid_fires_when_max_age_is_zero(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header="max-age=0"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.hsts_header_invalid" in {f.rule_id for f in result.findings}


def test_hsts_invalid_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.hsts_header_invalid" not in {f.rule_id for f in result.findings}


# --- X-Frame-Options invalid ---


def test_x_frame_options_invalid_does_not_fire_for_deny(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header="DENY"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_invalid" not in {f.rule_id for f in result.findings}


def test_x_frame_options_invalid_does_not_fire_for_sameorigin(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header="SAMEORIGIN"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_invalid" not in {f.rule_id for f in result.findings}


def test_x_frame_options_invalid_fires_for_allowall(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header="ALLOWALL"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_invalid" in {f.rule_id for f in result.findings}


def test_x_frame_options_invalid_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_invalid" not in {f.rule_id for f in result.findings}


# --- X-Content-Type-Options invalid ---


def test_x_content_type_options_invalid_does_not_fire_for_nosniff(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_content_type_options_header="nosniff"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_content_type_options_invalid" not in {f.rule_id for f in result.findings}


def test_x_content_type_options_invalid_fires_for_bad_value(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_content_type_options_header="sniff"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_content_type_options_invalid" in {f.rule_id for f in result.findings}


def test_x_content_type_options_invalid_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_content_type_options_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_content_type_options_invalid" not in {f.rule_id for f in result.findings}


# --- Referrer-Policy unsafe ---


def test_referrer_policy_unsafe_fires_for_unsafe_url(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(referrer_policy_header="unsafe-url"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_unsafe" in {f.rule_id for f in result.findings}


def test_referrer_policy_unsafe_does_not_fire_for_strict_origin(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(referrer_policy_header="strict-origin-when-cross-origin"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_unsafe" not in {f.rule_id for f in result.findings}


def test_referrer_policy_unsafe_does_not_fire_for_no_referrer(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(referrer_policy_header="no-referrer"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_unsafe" not in {f.rule_id for f in result.findings}


def test_referrer_policy_unsafe_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(referrer_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_unsafe" not in {f.rule_id for f in result.findings}


# --- Mutual exclusivity: missing vs invalid never both fire ---


def test_hsts_missing_and_invalid_are_mutually_exclusive(monkeypatch) -> None:
    """When HSTS is present but invalid, only invalid fires, not missing."""
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header="includeSubDomains"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_header_invalid" in rule_ids
    assert "external.hsts_header_missing" not in rule_ids


def test_x_frame_options_missing_and_invalid_are_mutually_exclusive(monkeypatch) -> None:
    """When X-Frame-Options is present but invalid, only invalid fires, not missing."""
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header="ALLOWALL"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.x_frame_options_invalid" in rule_ids
    assert "external.x_frame_options_missing" not in rule_ids


# --- HEAD + GET fallback ---


def test_get_fallback_on_head_405(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target, _ = _setup_head_fallback_probe(monkeypatch, head_status=405)
    result = _probe_target(target)

    assert result.has_http_response
    assert result.effective_method == "GET"
    assert result.status_code == 200


def test_get_fallback_on_head_501(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target, _ = _setup_head_fallback_probe(monkeypatch, head_status=501)
    result = _probe_target(target)

    assert result.effective_method == "GET"
    assert result.status_code == 200


def test_successful_head_does_not_trigger_get_fallback(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")
    methods_called = []

    def fake_try(probe_target, method):
        methods_called.append(method)
        return ProbeAttempt(
            target=probe_target,
            tcp_open=True,
            effective_method="HEAD",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        )

    monkeypatch.setattr("webconf_audit.external.recon._is_tcp_port_open", lambda h, p: True)
    monkeypatch.setattr("webconf_audit.external.recon._try_http_method", fake_try)

    result = _probe_target(target)
    assert result.effective_method == "HEAD"
    assert methods_called == ["HEAD"]


def test_get_fallback_when_head_fails_after_tcp_open(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target, _ = _setup_head_fallback_probe(
        monkeypatch, head_status=None, head_error="Connection reset by peer"
    )
    result = _probe_target(target)

    assert result.effective_method == "GET"
    assert result.status_code == 200


def test_effective_method_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(effective_method="GET"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["effective_method"] == "GET"
    assert not any(diagnostic.startswith("effective_method:") for diagnostic in result.diagnostics)


# --- Additional collected headers ---


def test_content_type_header_captured(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(content_type_header="text/html; charset=utf-8"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["content_type_header"] == "text/html; charset=utf-8"


def test_x_powered_by_header_captured(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_powered_by_header="PHP/8.2.0"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["x_powered_by_header"] == "PHP/8.2.0"


def test_x_aspnet_version_header_captured(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["x_aspnet_version_header"] == "4.0.30319"


def test_additional_response_headers_captured(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            cache_control_header="no-store",
            x_dns_prefetch_control_header="off",
            cross_origin_embedder_policy_header="require-corp",
            cross_origin_opener_policy_header="same-origin",
            cross_origin_resource_policy_header="same-origin",
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    metadata = result.metadata["probe_attempts"][0]
    assert metadata["cache_control_header"] == "no-store"
    assert metadata["x_dns_prefetch_control_header"] == "off"
    assert metadata["cross_origin_embedder_policy_header"] == "require-corp"
    assert metadata["cross_origin_opener_policy_header"] == "same-origin"
    assert metadata["cross_origin_resource_policy_header"] == "same-origin"


def test_try_http_method_collects_additional_response_headers(monkeypatch) -> None:
    from webconf_audit.external.recon import _try_http_method

    class DummyMessage:
        def get_all(self, _name: str) -> list[str]:
            return []

    class DummyResponse:
        status = 200
        reason = "OK"
        msg = DummyMessage()

        def __init__(self) -> None:
            self.headers = {
                "Cache-Control": "no-store",
                "X-DNS-Prefetch-Control": "off",
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin",
            }

        def getheader(self, name: str) -> str | None:
            return self.headers.get(name)

        def read(self, *_args) -> bytes:
            return b""

    class DummyConnection:
        def __init__(self) -> None:
            self.sock = None

        def request(self, _method: str, _path: str) -> None:
            return None

        def getresponse(self) -> DummyResponse:
            return DummyResponse()

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_connection",
        lambda _probe_target: DummyConnection(),
    )

    attempt = _try_http_method(
        ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
        "HEAD",
    )

    assert attempt.cache_control_header == "no-store"
    assert attempt.x_dns_prefetch_control_header == "off"
    assert attempt.cross_origin_embedder_policy_header == "require-corp"
    assert attempt.cross_origin_opener_policy_header == "same-origin"
    assert attempt.cross_origin_resource_policy_header == "same-origin"


def test_try_http_method_handles_http_exception_as_probe_failure(monkeypatch) -> None:
    from webconf_audit.external.recon import _try_http_method

    class DummyConnection:
        def __init__(self) -> None:
            self.sock = None

        def request(self, _method: str, _path: str) -> None:
            return None

        def getresponse(self):
            raise http.client.BadStatusLine("\x15\x03\x03")

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_connection",
        lambda _probe_target: DummyConnection(),
    )

    attempt = _try_http_method(
        ProbeTarget(scheme="http", host="example.com", port=443, path="/"),
        "HEAD",
    )

    assert attempt.tcp_open is True
    assert attempt.status_code is None
    assert attempt.error_message is not None
    assert "\\x15\\x03\\x03" not in attempt.error_message


@pytest.mark.parametrize(
    ("helper_name", "expected_url", "expected_path"),
    [
        ("_try_options_request", None, None),
        ("_try_sensitive_path", "http://example.com/", "/"),
        ("_try_error_page_probe", "http://example.com/", None),
    ],
)
def test_auxiliary_probes_handle_http_exception_as_probe_failure(
    monkeypatch,
    helper_name: str,
    expected_url: str | None,
    expected_path: str | None,
) -> None:
    import webconf_audit.external.recon as recon

    class DummyConnection:
        def request(self, _method: str, _path: str) -> None:
            return None

        def getresponse(self):
            raise http.client.BadStatusLine("\x15\x03\x03")

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_connection",
        lambda _probe_target: DummyConnection(),
    )

    helper = getattr(recon, helper_name)
    result = helper(ProbeTarget(scheme="http", host="example.com", port=80, path="/"))

    assert result.error_message
    assert getattr(result, "status_code", None) is None
    if expected_url is not None:
        assert getattr(result, "url", None) == expected_url
    if expected_path is not None:
        assert getattr(result, "path", None) == expected_path


# --- X-Powered-By presence rule ---


def test_x_powered_by_present_fires_when_header_set(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_powered_by_header="Express"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    findings = [
        f for f in result.findings
        if f.rule_id == "external.x_powered_by_header_present"
    ]
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.details == "X-Powered-By: Express"


def test_x_powered_by_present_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_powered_by_header_present" not in {f.rule_id for f in result.findings}


# --- X-AspNet-Version presence rule ---


def test_x_aspnet_version_present_fires_when_header_set(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    findings = [
        f for f in result.findings
        if f.rule_id == "external.x_aspnet_version_header_present"
    ]
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.details == "X-AspNet-Version: 4.0.30319"


def test_x_aspnet_version_present_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_aspnet_version_header_present" not in {f.rule_id for f in result.findings}


# --- Extended version disclosure ---


def test_version_disclosure_fires_for_server_header(monkeypatch) -> None:
    """Apache Server header version disclosure now uses the Apache-specific rule."""
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58"),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    version_findings = [
        f for f in result.findings
        if f.rule_id == "external.apache.version_disclosed_in_server_header"
    ]
    assert len(version_findings) >= 1
    assert "Apache/2.4.58" in version_findings[0].description


def test_version_disclosure_fires_for_x_powered_by_with_version(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_powered_by_header="PHP/8.2.0"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    version_findings = [f for f in result.findings if f.rule_id == "external.server_version_disclosed"]
    assert len(version_findings) >= 1
    assert "X-Powered-By" in version_findings[0].description


def test_version_disclosure_fires_for_x_aspnet_version(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    version_findings = [f for f in result.findings if f.rule_id == "external.server_version_disclosed"]
    assert len(version_findings) >= 1
    assert "X-AspNet-Version" in version_findings[0].description


def test_x_powered_by_express_triggers_presence_but_not_version_disclosure(monkeypatch) -> None:
    """Express without version number: presence rule yes, version disclosure no."""
    probe_attempts = [
        _https_probe_with_headers(x_powered_by_header="Express"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.x_powered_by_header_present" in rule_ids
    assert "external.server_version_disclosed" not in rule_ids


# --- Coexistence: presence + version disclosure can both fire ---


def test_x_powered_by_with_version_fires_both_presence_and_disclosure(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_powered_by_header="PHP/8.2.0"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.x_powered_by_header_present" in rule_ids
    assert "external.server_version_disclosed" in rule_ids


def test_x_aspnet_version_fires_both_presence_and_disclosure(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.x_aspnet_version_header_present" in rule_ids
    assert "external.server_version_disclosed" in rule_ids


# --- Disclosure rules apply to HTTP too, not only HTTPS ---


def test_x_powered_by_fires_for_http_response(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            x_powered_by_header="PHP/8.2.0",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.x_powered_by_header_present" in rule_ids


# --- CORS / Allow header metadata ---


def test_access_control_allow_origin_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(access_control_allow_origin_header="*"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["access_control_allow_origin_header"] == "*"


def test_access_control_allow_credentials_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(access_control_allow_credentials_header="true"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["access_control_allow_credentials_header"] == "true"


def test_allow_header_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(allow_header="GET, HEAD, OPTIONS"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["allow_header"] == "GET, HEAD, OPTIONS"


# --- CORS wildcard origin rule ---


def test_cors_wildcard_origin_fires_for_star(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(access_control_allow_origin_header="*"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_origin" in {f.rule_id for f in result.findings}


def test_cors_wildcard_origin_does_not_fire_when_absent(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_origin" not in {f.rule_id for f in result.findings}


def test_cors_wildcard_origin_does_not_fire_for_concrete_origin(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(access_control_allow_origin_header="https://example.com"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_origin" not in {f.rule_id for f in result.findings}


# --- CORS wildcard with credentials rule ---


def test_cors_wildcard_with_credentials_fires(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            access_control_allow_origin_header="*",
            access_control_allow_credentials_header="true",
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_with_credentials" in {f.rule_id for f in result.findings}


def test_cors_wildcard_with_credentials_case_insensitive(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            access_control_allow_origin_header="*",
            access_control_allow_credentials_header="True",
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_with_credentials" in {f.rule_id for f in result.findings}


def test_cors_wildcard_with_credentials_does_not_fire_for_concrete_origin(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            access_control_allow_origin_header="https://example.com",
            access_control_allow_credentials_header="true",
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_with_credentials" not in {f.rule_id for f in result.findings}


def test_cors_wildcard_with_credentials_does_not_fire_without_credentials(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(access_control_allow_origin_header="*"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_with_credentials" not in {f.rule_id for f in result.findings}


# --- TRACE method allowed rule ---


def test_trace_method_allowed_fires_when_trace_in_allow(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(allow_header="GET, HEAD, TRACE, OPTIONS"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_allowed" in {f.rule_id for f in result.findings}


def test_trace_method_allowed_does_not_fire_without_trace(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(allow_header="GET, HEAD, OPTIONS"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_allowed" not in {f.rule_id for f in result.findings}


def test_trace_method_allowed_does_not_fire_when_allow_absent(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_allowed" not in {f.rule_id for f in result.findings}


def test_trace_method_allowed_handles_case_and_spaces(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(allow_header="get , head , trace , options"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_allowed" in {f.rule_id for f in result.findings}


def test_trace_method_allowed_fires_for_http_response(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="apache",
            allow_header="GET, HEAD, TRACE",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_allowed" in {f.rule_id for f in result.findings}


# --- Allow header preservation across HEAD->GET fallback ---


def test_allow_header_preserved_from_head_405_to_get_fallback(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")

    def fake_try(probe_target, method):
        if method == "HEAD":
            return ProbeAttempt(
                target=probe_target,
                tcp_open=True,
                effective_method="HEAD",
                status_code=405,
                reason_phrase="Method Not Allowed",
                server_header="apache",
                allow_header="GET, HEAD, TRACE",
            )
        return ProbeAttempt(
            target=probe_target,
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="apache",
            **_ALL_SECURITY_HEADERS,
        )

    monkeypatch.setattr("webconf_audit.external.recon._is_tcp_port_open", lambda h, p: True)
    monkeypatch.setattr("webconf_audit.external.recon._try_http_method", fake_try)

    result = _probe_target(target)
    assert result.effective_method == "GET"
    assert result.status_code == 200
    assert result.allow_header == "GET, HEAD, TRACE"


# --- CORS mutual exclusion: wildcard+credentials suppresses plain wildcard ---


def test_cors_wildcard_and_credentials_suppresses_plain_wildcard_rule(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            access_control_allow_origin_header="*",
            access_control_allow_credentials_header="true",
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cors_wildcard_with_credentials" in rule_ids
    assert "external.cors_wildcard_origin" not in rule_ids


# --- Cookie helper tests ---


def test_parse_cookie_extracts_name_and_attributes() -> None:
    from webconf_audit.external.recon._cookie import parse_cookie

    cookie = parse_cookie("session_id=abc123; Secure; HttpOnly; SameSite=Lax; Path=/")
    assert cookie.name == "session_id"
    assert cookie.has_secure is True
    assert cookie.has_httponly is True
    assert cookie.samesite_value == "Lax"
    assert cookie.domain_value is None
    assert cookie.path_value == "/"


def test_parse_cookie_case_insensitive_attributes() -> None:
    from webconf_audit.external.recon._cookie import parse_cookie

    cookie = parse_cookie("sid=x; secure; HTTPONLY; samesite=Strict; domain=example.com")
    assert cookie.has_secure is True
    assert cookie.has_httponly is True
    assert cookie.samesite_value == "Strict"
    assert cookie.domain_value == "example.com"
    assert cookie.path_value is None


def test_parse_cookie_missing_attributes() -> None:
    from webconf_audit.external.recon._cookie import parse_cookie

    cookie = parse_cookie("sid=x; Path=/")
    assert cookie.name == "sid"
    assert cookie.has_secure is False
    assert cookie.has_httponly is False
    assert cookie.samesite_value is None
    assert cookie.domain_value is None
    assert cookie.path_value == "/"


def test_is_session_like_cookie_matches() -> None:
    from webconf_audit.external.recon._cookie import is_session_like_cookie

    assert is_session_like_cookie("PHPSESSID") is True
    assert is_session_like_cookie("session_id") is True
    assert is_session_like_cookie("auth_token") is True
    assert is_session_like_cookie("JWT") is True
    assert is_session_like_cookie("connect.sid") is True
    assert is_session_like_cookie("my_token") is True


def test_is_session_like_cookie_rejects_non_session() -> None:
    from webconf_audit.external.recon._cookie import is_session_like_cookie

    assert is_session_like_cookie("_ga") is False
    assert is_session_like_cookie("theme") is False
    assert is_session_like_cookie("lang") is False


def test_is_session_like_cookie_excludes_csrf_cookies() -> None:
    from webconf_audit.external.recon._cookie import is_session_like_cookie

    assert is_session_like_cookie("csrftoken") is False
    assert is_session_like_cookie("xsrf-token") is False
    assert is_session_like_cookie("csrf-token") is False
    assert is_session_like_cookie("CSRFTOKEN") is False


def test_csrf_cookies_do_not_trigger_cookie_rules(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("csrftoken=abc; Path=/", "xsrf-token=xyz; Path=/"),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    cookie_rules = {
        "external.cookie_missing_secure_on_https",
        "external.cookie_missing_httponly",
        "external.cookie_missing_samesite",
    }
    assert not cookie_rules.intersection({f.rule_id for f in result.findings})


# --- Set-Cookie collection metadata ---


def test_set_cookie_headers_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure", "lang=en"),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    cookies = result.metadata["probe_attempts"][0]["set_cookie_headers"]
    assert cookies == ["session_id=abc; Secure", "lang=en"]


def test_set_cookie_empty_when_no_cookies(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["set_cookie_headers"] == []


# --- Cookie missing Secure on HTTPS ---


def test_cookie_missing_secure_fires_on_https(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; HttpOnly; SameSite=Lax",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    secure_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_secure_on_https"]
    assert len(secure_findings) == 1
    assert "session_id" in secure_findings[0].description


def test_cookie_missing_secure_does_not_fire_on_http(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc; HttpOnly",),
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cookie_missing_secure_on_https" not in {f.rule_id for f in result.findings}


def test_cookie_missing_secure_does_not_fire_when_secure_present(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure; HttpOnly; SameSite=Lax",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cookie_missing_secure_on_https" not in {f.rule_id for f in result.findings}


# --- Cookie missing HttpOnly ---


def test_cookie_missing_httponly_fires(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure; SameSite=Lax",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    httponly_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_httponly"]
    assert len(httponly_findings) == 1
    assert "session_id" in httponly_findings[0].description


def test_cookie_missing_httponly_does_not_fire_when_present(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure; HttpOnly; SameSite=Lax",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cookie_missing_httponly" not in {f.rule_id for f in result.findings}


# --- Cookie missing SameSite ---


def test_cookie_missing_samesite_fires(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure; HttpOnly",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    samesite_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_samesite"]
    assert len(samesite_findings) == 1
    assert "session_id" in samesite_findings[0].description


def test_cookie_missing_samesite_does_not_fire_when_present(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure; HttpOnly; SameSite=Strict",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cookie_missing_samesite" not in {f.rule_id for f in result.findings}


# --- No findings for non-session cookies ---


def test_no_cookie_findings_for_non_session_cookie(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("_ga=GA1.2.123; Path=/",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    cookie_rules = {
        "external.cookie_missing_secure_on_https",
        "external.cookie_missing_httponly",
        "external.cookie_missing_samesite",
    }
    assert not cookie_rules.intersection({f.rule_id for f in result.findings})


# --- Cookie prefix contracts ---


def test_cookie_prefix_contract_fires_for_invalid_host_cookie(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=(
                "__Host-session=abc; Secure; HttpOnly; SameSite=Lax; Domain=example.com; Path=/app",
            ),
        ),
        _http_redirect_probe(),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "external.cookie_prefix_contract_violated"
    ]
    assert len(findings) == 1
    assert "__Host-session" in findings[0].description
    assert "Domain='example.com'" in findings[0].description
    assert "Path='/app'" in findings[0].description


def test_cookie_prefix_contract_fires_for_host_cookie_without_explicit_path(
    monkeypatch,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("__Host-session=abc; Secure; HttpOnly; SameSite=Lax",),
        ),
        _http_redirect_probe(),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "external.cookie_prefix_contract_violated"
    ]
    assert len(findings) == 1
    assert "__Host-session" in findings[0].description
    assert "Path=/ is missing" in findings[0].description


def test_cookie_prefix_contract_fires_for_secure_prefix_on_http(monkeypatch) -> None:
    probe_attempts = [
        _http_probe_with_headers(
            set_cookie_headers=("__Secure-auth=abc; Secure; HttpOnly; SameSite=Lax",),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "external.cookie_prefix_contract_violated"
    ]
    assert len(findings) == 1
    assert "__Secure-auth" in findings[0].description
    assert "observed over HTTP" in findings[0].description


def test_cookie_prefix_contract_does_not_fire_for_valid_host_cookie(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=(
                "__Host-session=abc; Secure; HttpOnly; SameSite=Lax; Path=/",
            ),
        ),
        _http_redirect_probe(),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.cookie_prefix_contract_violated" not in {
        finding.rule_id for finding in result.findings
    }


def test_cookie_prefix_contract_applies_to_non_session_cookie(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("__Host-csrf=abc; Secure; Domain=example.com; Path=/",),
        ),
        _http_redirect_probe(),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.cookie_prefix_contract_violated" in {
        finding.rule_id for finding in result.findings
    }


# --- Multiple cookies with mixed posture ---


def test_multiple_cookies_mixed_posture(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=(
                "session_id=abc; Secure; HttpOnly; SameSite=Lax",
                "auth_token=xyz; Path=/",
            ),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    secure_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_secure_on_https"]
    assert len(secure_findings) == 1
    assert "auth_token" in secure_findings[0].description

    httponly_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_httponly"]
    assert len(httponly_findings) == 1
    assert "auth_token" in httponly_findings[0].description

    samesite_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_samesite"]
    assert len(samesite_findings) == 1
    assert "auth_token" in samesite_findings[0].description


# --- TLS observation metadata ---
