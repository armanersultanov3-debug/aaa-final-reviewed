from __future__ import annotations

import hashlib
from email.message import Message

from tests.external_helpers import (
    ProbeTarget,
    _analyze_with_probe_attempts,
    _https_probe_with_headers,
)
from webconf_audit.external.html_recon import parse_html_recon
from webconf_audit.external.recon import (
    _BODY_SNIPPET_MAX_BYTES,
    _build_https_request_bytes,
    _HTML_RECON_BODY_MAX_BYTES,
    _read_get_body_observations,
)


class _FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        content_type: str | None = "text/html; charset=utf-8",
        content_length: str | None = None,
    ) -> None:
        self._remaining = body
        self.read_sizes: list[int] = []
        self.msg = Message()
        if content_type is not None:
            self.msg["Content-Type"] = content_type
        if content_length is not None:
            self.msg["Content-Length"] = content_length

    def read(self, size: int | None = None) -> bytes:
        if size is None:
            size = len(self._remaining)
        self.read_sizes.append(size)
        chunk = self._remaining[:size]
        self._remaining = self._remaining[size:]
        return chunk

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.msg.get(name, default)


def test_cross_origin_script_without_sri_fires(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            html_recon=parse_html_recon(
                '<html><script src="//cdn.example.net/app.js"></script></html>'
            )
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "external.script_src_missing_sri"
    ]
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].metadata["script_src"] == "//cdn.example.net/app.js"


def test_cross_origin_script_with_sri_does_not_fire(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            html_recon=parse_html_recon(
                '<html><script src="https://cdn.example.net/app.js" '
                'integrity="sha384-deadbeef" crossorigin="anonymous"></script></html>'
            )
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.script_src_missing_sri" not in {
        finding.rule_id for finding in result.findings
    }


def test_same_origin_script_without_sri_does_not_fire(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            html_recon=parse_html_recon(
                '<html><script src="/static/app.js"></script></html>'
            )
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.script_src_missing_sri" not in {
        finding.rule_id for finding in result.findings
    }


def test_unsafe_inline_with_inline_script_stays_medium(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header="default-src 'self'; script-src 'unsafe-inline'",
            html_recon=parse_html_recon(
                "<html><script>console.log('inline')</script></html>"
            ),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "external.content_security_policy_unsafe_inline"
    )
    assert finding.severity == "medium"
    assert finding.metadata["inline_script_count"] == 1


def test_unsafe_inline_without_inline_scripts_downgrades_to_info(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            content_security_policy_header="default-src 'self'; script-src 'unsafe-inline'",
            html_recon=parse_html_recon(
                '<html><script src="https://cdn.example.net/app.js" '
                'integrity="sha384-deadbeef"></script></html>'
            ),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "external.content_security_policy_unsafe_inline"
    )
    assert finding.severity == "info"
    assert finding.metadata["inline_script_count"] == 0


def test_nonce_reuse_uses_inline_script_nonce_corroboration(monkeypatch) -> None:
    header_nonce = "'nonce-shared123'"
    nonce_value = "shared123"
    probe_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            content_security_policy_header=f"default-src 'self'; script-src 'self' {header_nonce}",
            html_recon=parse_html_recon(
                f'<html><script nonce="{nonce_value}">console.log(1)</script></html>'
            ),
        ),
        _https_probe_with_headers(
            target=ProbeTarget(
                scheme="https",
                host="example.com",
                port=443,
                path="/account",
            ),
            content_security_policy_header=f"default-src 'self'; script-src 'self' {header_nonce}",
            html_recon=parse_html_recon(
                f'<html><script nonce="{nonce_value}">console.log(2)</script></html>'
            ),
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "external.content_security_policy_nonce_reused"
    )
    nonce_fingerprint = hashlib.sha256(header_nonce.encode("utf-8")).hexdigest()[:12]
    assert finding.metadata["corroborated_inline_response_count"] == 2
    assert f"sha256:{nonce_fingerprint}" in finding.description
    assert "inline script tags using that nonce" in finding.description


def test_non_html_response_skips_html_parsing() -> None:
    response = _FakeResponse(
        b"<html><script src='https://cdn.example.net/app.js'></script></html>",
        content_type="application/json",
    )

    body_snippet, html_recon = _read_get_body_observations(
        response,
        status_code=200,
        content_type_header="application/json",
    )

    assert html_recon is None
    assert body_snippet is not None
    assert response.read_sizes == [_BODY_SNIPPET_MAX_BYTES]


def test_oversize_html_response_skips_html_parsing() -> None:
    oversize_body = b"a" * (_HTML_RECON_BODY_MAX_BYTES + 128)
    response = _FakeResponse(
        oversize_body,
        content_length=str(len(oversize_body)),
    )

    body_snippet, html_recon = _read_get_body_observations(
        response,
        status_code=200,
        content_type_header="text/html; charset=utf-8",
    )

    assert html_recon is None
    assert body_snippet == "a" * _BODY_SNIPPET_MAX_BYTES
    assert response.read_sizes == [_BODY_SNIPPET_MAX_BYTES]


def test_https_request_bytes_request_identity_encoding() -> None:
    request_bytes = _build_https_request_bytes(
        ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
        "GET",
    )

    assert b"Accept-Encoding: identity\r\n" in request_bytes
