from tests.external_helpers import (
    ProbeAttempt,
    ProbeTarget,
    RuntimeResponseObservation,
    UnknownHostProbe,
    _https_probe_with_headers,
    run_external_rules,
)


def _unknown_host_probe(
    *,
    disposition: str,
    baseline_status: int = 200,
    probe_status: int | None = 200,
    baseline_hash: str = "baseline-hash",
    probe_hash: str = "baseline-hash",
    error_message: str | None = None,
) -> UnknownHostProbe:
    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")
    return UnknownHostProbe(
        target=target,
        host_header="webconf-audit-unknown-host-test.invalid",
        disposition=disposition,
        baseline_response=RuntimeResponseObservation(
            url=target.url,
            host_header="example.com",
            status_code=baseline_status,
            reason_phrase="OK",
            body_sha256=baseline_hash,
            body_size=128,
            server_header="nginx",
            content_type_header="text/html",
        ),
        unknown_host_response=RuntimeResponseObservation(
            url=target.url,
            host_header="webconf-audit-unknown-host-test.invalid",
            status_code=probe_status,
            reason_phrase="OK" if probe_status is not None else None,
            body_sha256=probe_hash if probe_status is not None else None,
            body_size=128 if probe_status is not None else None,
            server_header="nginx" if probe_status is not None else None,
            content_type_header="text/html" if probe_status is not None else None,
            error_message=error_message,
        ),
    )


def _base_attempt() -> ProbeAttempt:
    return ProbeAttempt(
        target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
        tcp_open=True,
        status_code=200,
        reason_phrase="OK",
        server_header="nginx",
    )


def test_unknown_host_rule_fires_for_200_with_matching_body(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            unknown_host_probe=_unknown_host_probe(
                disposition="accepted_same_content",
            ),
        ),
    ]

    findings = [
        finding
        for finding in run_external_rules(probe_attempts, "example.com")
        if finding.rule_id == "external.unknown_host_runtime_response"
    ]
    assert len(findings) == 1
    assert "webconf-audit-unknown-host-test.invalid" in findings[0].description


def test_unknown_host_rule_does_not_fire_for_421_rejection(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            unknown_host_probe=_unknown_host_probe(
                disposition="rejected",
                probe_status=421,
            ),
        ),
    ]

    assert "external.unknown_host_runtime_response" not in {
        finding.rule_id for finding in run_external_rules(probe_attempts, "example.com")
    }


def test_unknown_host_rule_does_not_fire_for_200_with_different_body(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            unknown_host_probe=_unknown_host_probe(
                disposition="accepted_different_content",
                probe_hash="different-hash",
            ),
        ),
    ]

    assert "external.unknown_host_runtime_response" not in {
        finding.rule_id for finding in run_external_rules(probe_attempts, "example.com")
    }


def test_unknown_host_rule_does_not_fire_for_404_rejection(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            unknown_host_probe=_unknown_host_probe(
                disposition="rejected",
                probe_status=404,
            ),
        ),
    ]

    assert "external.unknown_host_runtime_response" not in {
        finding.rule_id for finding in run_external_rules(probe_attempts, "example.com")
    }


def test_unknown_host_rule_does_not_fire_for_tls_level_rejection(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            unknown_host_probe=_unknown_host_probe(
                disposition="tls_rejected",
                probe_status=None,
                error_message="tlsv1 alert unrecognized name",
            ),
        ),
    ]

    assert "external.unknown_host_runtime_response" not in {
        finding.rule_id for finding in run_external_rules(probe_attempts, "example.com")
    }


def test_probe_unknown_host_response_classifies_421_as_rejected(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_unknown_host_response

    responses = iter(
        (
            RuntimeResponseObservation(
                url="https://example.com/",
                host_header="example.com",
                status_code=200,
                reason_phrase="OK",
                body_sha256="baseline",
                body_size=64,
                server_header="nginx",
                content_type_header="text/html",
            ),
            RuntimeResponseObservation(
                url="https://example.com/",
                host_header="webconf-audit-unknown-host-test.invalid",
                status_code=421,
                reason_phrase="Misdirected Request",
                body_sha256="reject",
                body_size=0,
                server_header="nginx",
                content_type_header="text/html",
            ),
        )
    )

    monkeypatch.setattr(
        "webconf_audit.external.recon._unknown_host_probe_hostname",
        lambda: "webconf-audit-unknown-host-test.invalid",
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._try_runtime_response",
        lambda *_args, **_kwargs: next(responses),
    )

    probe = _probe_unknown_host_response(_base_attempt())

    assert probe.disposition == "rejected"


def test_probe_unknown_host_response_classifies_matching_200_as_accepted_same_content(
    monkeypatch,
) -> None:
    from webconf_audit.external.recon import _probe_unknown_host_response

    responses = iter(
        (
            RuntimeResponseObservation(
                url="https://example.com/",
                host_header="example.com",
                status_code=200,
                reason_phrase="OK",
                body_sha256="baseline",
                body_size=64,
                server_header="nginx",
                content_type_header="text/html",
            ),
            RuntimeResponseObservation(
                url="https://example.com/",
                host_header="webconf-audit-unknown-host-test.invalid",
                status_code=200,
                reason_phrase="OK",
                body_sha256="baseline",
                body_size=64,
                server_header="nginx",
                content_type_header="text/html",
            ),
        )
    )

    monkeypatch.setattr(
        "webconf_audit.external.recon._unknown_host_probe_hostname",
        lambda: "webconf-audit-unknown-host-test.invalid",
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._try_runtime_response",
        lambda *_args, **_kwargs: next(responses),
    )

    probe = _probe_unknown_host_response(_base_attempt())

    assert probe.disposition == "accepted_same_content"


def test_probe_unknown_host_response_classifies_different_200_as_accepted_different_content(
    monkeypatch,
) -> None:
    from webconf_audit.external.recon import _probe_unknown_host_response

    responses = iter(
        (
            RuntimeResponseObservation(
                url="https://example.com/",
                host_header="example.com",
                status_code=200,
                reason_phrase="OK",
                body_sha256="baseline",
                body_size=64,
                server_header="nginx",
                content_type_header="text/html",
            ),
            RuntimeResponseObservation(
                url="https://example.com/",
                host_header="webconf-audit-unknown-host-test.invalid",
                status_code=200,
                reason_phrase="OK",
                body_sha256="different",
                body_size=64,
                server_header="nginx",
                content_type_header="text/html",
            ),
        )
    )

    monkeypatch.setattr(
        "webconf_audit.external.recon._unknown_host_probe_hostname",
        lambda: "webconf-audit-unknown-host-test.invalid",
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._try_runtime_response",
        lambda *_args, **_kwargs: next(responses),
    )

    probe = _probe_unknown_host_response(_base_attempt())

    assert probe.disposition == "accepted_different_content"


def test_probe_unknown_host_response_classifies_404_as_rejected(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_unknown_host_response

    responses = iter(
        (
            RuntimeResponseObservation(
                url="https://example.com/",
                host_header="example.com",
                status_code=200,
                reason_phrase="OK",
                body_sha256="baseline",
                body_size=64,
                server_header="nginx",
                content_type_header="text/html",
            ),
            RuntimeResponseObservation(
                url="https://example.com/",
                host_header="webconf-audit-unknown-host-test.invalid",
                status_code=404,
                reason_phrase="Not Found",
                body_sha256="reject",
                body_size=0,
                server_header="nginx",
                content_type_header="text/html",
            ),
        )
    )

    monkeypatch.setattr(
        "webconf_audit.external.recon._unknown_host_probe_hostname",
        lambda: "webconf-audit-unknown-host-test.invalid",
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._try_runtime_response",
        lambda *_args, **_kwargs: next(responses),
    )

    probe = _probe_unknown_host_response(_base_attempt())

    assert probe.disposition == "rejected"


def test_probe_unknown_host_response_classifies_tls_rejection(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_unknown_host_response

    responses = iter(
        (
            RuntimeResponseObservation(
                url="https://example.com/",
                host_header="example.com",
                status_code=200,
                reason_phrase="OK",
                body_sha256="baseline",
                body_size=64,
                server_header="nginx",
                content_type_header="text/html",
            ),
            RuntimeResponseObservation(
                url="https://example.com/",
                host_header="webconf-audit-unknown-host-test.invalid",
                error_message="tlsv1 alert unrecognized name",
            ),
        )
    )

    monkeypatch.setattr(
        "webconf_audit.external.recon._unknown_host_probe_hostname",
        lambda: "webconf-audit-unknown-host-test.invalid",
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._try_runtime_response",
        lambda *_args, **_kwargs: next(responses),
    )

    probe = _probe_unknown_host_response(_base_attempt())

    assert probe.disposition == "tls_rejected"
