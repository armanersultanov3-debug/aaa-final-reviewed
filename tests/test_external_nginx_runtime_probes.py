from __future__ import annotations

from tests.external_helpers import (
    OptionsObservation,
    ProbeAttempt,
    ProbeTarget,
    _ALL_SECURITY_HEADERS,
    _analyze_with_probe_attempts,
    _http_probe_with_headers,
    _http_redirect_probe,
    _https_probe_with_headers,
)

_NEW_RULE_IDS = {
    "external.nginx.default_index_page_body",
    "external.nginx.redirect_target_unexpected",
}


def test_root_head_200_triggers_get_body_follow_up(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")
    methods_called: list[str] = []

    def fake_try_http_method(probe_target: ProbeTarget, method: str) -> ProbeAttempt:
        methods_called.append(method)
        if method == "HEAD":
            return ProbeAttempt(
                target=probe_target,
                tcp_open=True,
                effective_method="HEAD",
                status_code=200,
                reason_phrase="OK",
                server_header="nginx/1.25.5",
                **_ALL_SECURITY_HEADERS,
            )
        return ProbeAttempt(
            target=probe_target,
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.25.5",
            body_snippet="Welcome to nginx!",
            **_ALL_SECURITY_HEADERS,
        )

    monkeypatch.setattr("webconf_audit.external.recon._is_tcp_port_open", lambda h, p: True)
    monkeypatch.setattr(
        "webconf_audit.external.recon._try_http_method",
        fake_try_http_method,
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._try_options_request",
        lambda probe_target: OptionsObservation(),
    )

    result = _probe_target(target)

    assert methods_called == ["HEAD", "GET"]
    assert result.effective_method == "GET"
    assert result.body_snippet == "Welcome to nginx!"


def test_nginx_runtime_probes_fire_on_http_200_default_body(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx/1.25.5",
            body_snippet="<html><body>Application homepage</body></html>",
        ),
        _http_probe_with_headers(
            server_header="nginx/1.25.5",
            body_snippet=(
                "<html><title>Welcome to nginx!</title><body>"
                "Welcome to nginx! If you see this page, the nginx web server "
                "is successfully installed and working.</body></html>"
            ),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert _new_rule_ids(result) == {
        "external.nginx.default_index_page_body",
        "external.nginx.redirect_target_unexpected",
    }


def test_nginx_runtime_redirect_probe_respects_https_redirect(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx/1.25.5",
            body_snippet=(
                "<html><title>Welcome to nginx!</title><body>"
                "Welcome to nginx! If you see this page, the nginx web server "
                "is successfully installed and working.</body></html>"
            ),
        ),
        _http_redirect_probe(server_header="nginx/1.25.5"),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert _new_rule_ids(result) == {"external.nginx.default_index_page_body"}


def test_nginx_runtime_probes_require_nginx_fingerprint(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="Apache/2.4.58",
            body_snippet="<html><body>Application homepage</body></html>",
        ),
        _http_probe_with_headers(
            server_header="Apache/2.4.58",
            body_snippet=(
                "<html><title>Welcome to nginx!</title><body>"
                "Welcome to nginx! If you see this page, the nginx web server "
                "is successfully installed and working.</body></html>"
            ),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert _new_rule_ids(result) == set()


def test_nginx_default_index_page_body_requires_non_empty_body(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx/1.25.5",
            body_snippet="<html><body>Application homepage</body></html>",
        ),
        _http_probe_with_headers(
            server_header="nginx/1.25.5",
            body_snippet=None,
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.nginx.default_index_page_body" not in _new_rule_ids(result)
    assert "external.nginx.redirect_target_unexpected" not in _new_rule_ids(result)


def _new_rule_ids(result) -> set[str]:
    return {
        finding.rule_id
        for finding in result.findings
        if finding.rule_id in _NEW_RULE_IDS
    }
