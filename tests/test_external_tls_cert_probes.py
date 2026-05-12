from tests.external_helpers import (
    SCTObservation,
    TLSCertificateObservation,
    TLSInfo,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
)


def _leaf_certificate(*, self_signed: bool = False) -> TLSCertificateObservation:
    issuer = "commonName=example.com" if self_signed else "commonName=Test CA"
    return TLSCertificateObservation(
        subject="commonName=example.com",
        issuer=issuer,
        signature_oid="1.2.840.113549.1.1.11",
        signature_name="sha256WithRSAEncryption",
        self_signed=self_signed,
    )


def _embedded_sct() -> SCTObservation:
    return SCTObservation(
        version="v1",
        log_id="00" * 32,
        timestamp="2026-05-12T00:00:00+00:00",
        entry_type="precertificate",
        signature_hash_algorithm="sha256",
        signature_algorithm="ecdsa",
    )


def test_tls_cert_probe_metadata_includes_ct_signature_and_must_staple(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Test CA",
        embedded_scts=(_embedded_sct(),),
        chain_certificates=(_leaf_certificate(),),
        chain_signature_algorithms=("sha256WithRSAEncryption (1.2.840.113549.1.1.11)",),
        cert_must_staple=True,
        ocsp_stapled=False,
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]

    assert tls_meta["embedded_scts"][0]["version"] == "v1"
    assert tls_meta["chain_certificates"][0]["signature_name"] == "sha256WithRSAEncryption"
    assert tls_meta["chain_signature_algorithms"] == [
        "sha256WithRSAEncryption (1.2.840.113549.1.1.11)"
    ]
    assert tls_meta["cert_must_staple"] is True


def test_tls_ct_log_evidence_missing_skips_when_embedded_scts_present(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Let's Encrypt R12",
        embedded_scts=(_embedded_sct(),),
        chain_certificates=(_leaf_certificate(),),
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.tls_ct_log_evidence_missing" not in {f.rule_id for f in result.findings}


def test_self_signed_certificate_skips_ct_and_signature_findings(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=example.com",
        chain_certificates=(
            TLSCertificateObservation(
                subject="commonName=example.com",
                issuer="commonName=example.com",
                signature_oid="1.2.840.113549.1.1.5",
                signature_name="sha1WithRSAEncryption",
                self_signed=True,
            ),
        ),
        chain_signature_algorithms=("sha1WithRSAEncryption (1.2.840.113549.1.1.5)",),
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}

    assert "external.tls_ct_log_evidence_missing" not in rule_ids
    assert "external.tls_weak_signature_algorithm" not in rule_ids


def test_tls_weak_signature_algorithm_fires_for_sha1_intermediate(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Intermediate CA",
        embedded_scts=(_embedded_sct(),),
        chain_certificates=(
            _leaf_certificate(),
            TLSCertificateObservation(
                subject="commonName=Intermediate CA",
                issuer="commonName=Root CA",
                signature_oid="1.2.840.113549.1.1.5",
                signature_name="sha1WithRSAEncryption",
                self_signed=False,
            ),
        ),
        chain_signature_algorithms=(
            "sha256WithRSAEncryption (1.2.840.113549.1.1.11)",
            "sha1WithRSAEncryption (1.2.840.113549.1.1.5)",
        ),
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    finding = next(
        f for f in result.findings
        if f.rule_id == "external.tls_weak_signature_algorithm"
    )
    assert "Intermediate CA" in finding.description
    assert "sha1WithRSAEncryption" in finding.location.details


def test_tls_must_staple_not_observed_fires_without_ocsp_staple(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Test CA",
        cert_must_staple=True,
        ocsp_stapled=False,
        chain_certificates=(_leaf_certificate(),),
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.tls_must_staple_not_observed" in {f.rule_id for f in result.findings}


def test_tls_must_staple_not_observed_skips_without_flag(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Test CA",
        cert_must_staple=False,
        ocsp_stapled=False,
        chain_certificates=(_leaf_certificate(),),
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.tls_must_staple_not_observed" not in {
        f.rule_id for f in result.findings
    }
