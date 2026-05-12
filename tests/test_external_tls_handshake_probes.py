from __future__ import annotations

from tests.external_helpers import (
    TLSInfo,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
)


def test_tls12_secure_renegotiation_not_observed_fires(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        renegotiation_info_observed=False,
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.tls_secure_renegotiation_not_observed" in {
        finding.rule_id for finding in result.findings
    }


def test_tls13_secure_renegotiation_not_observed_is_excluded(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        renegotiation_info_observed=False,
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.tls_secure_renegotiation_not_observed" not in {
        finding.rule_id for finding in result.findings
    }


def test_tls12_negotiated_compression_fires(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        negotiated_compression="deflate",
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.tls_negotiated_compression" in {
        finding.rule_id for finding in result.findings
    }


def test_tls13_negotiated_compression_is_excluded(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        negotiated_compression="deflate",
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.tls_negotiated_compression" not in {
        finding.rule_id for finding in result.findings
    }


def test_tls12_aead_cipher_does_not_fire(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cipher_name="AES_128_GCM",
        negotiated_cipher_is_aead=True,
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.tls_aead_cipher_not_negotiated" not in {
        finding.rule_id for finding in result.findings
    }


def test_tls12_cbc_cipher_fires(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cipher_name="AES_128_CBC_SHA",
        negotiated_cipher_is_aead=False,
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.tls_aead_cipher_not_negotiated" in {
        finding.rule_id for finding in result.findings
    }


def test_tls13_aead_rule_is_excluded(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_128_GCM_SHA256",
        negotiated_cipher_is_aead=False,
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.tls_aead_cipher_not_negotiated" not in {
        finding.rule_id for finding in result.findings
    }


def test_tls_handshake_observation_fields_appear_in_metadata(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        renegotiation_info_observed=False,
        negotiated_compression="deflate",
        negotiated_cipher_is_aead=False,
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]

    assert tls_meta["renegotiation_info_observed"] is False
    assert tls_meta["negotiated_compression"] == "deflate"
    assert tls_meta["negotiated_cipher_is_aead"] is False
