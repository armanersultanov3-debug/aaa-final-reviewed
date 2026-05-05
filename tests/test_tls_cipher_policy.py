from webconf_audit.tls_cipher_policy import analyze_cipher_policy


def test_cipher_policy_reports_enabled_weak_markers() -> None:
    assessment = analyze_cipher_policy("ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA")

    assert assessment.weak_markers == ("RC4",)
    assert assessment.has_issue


def test_cipher_policy_ignores_disabled_weak_markers() -> None:
    assessment = analyze_cipher_policy("HIGH:!aNULL:!MD5:-DES")

    assert assessment.weak_markers == ()
    assert not assessment.missing_forward_secrecy
    assert not assessment.missing_aead
    assert not assessment.has_issue


def test_cipher_policy_reports_missing_forward_secrecy_for_static_rsa_gcm() -> None:
    assessment = analyze_cipher_policy("AES256-GCM-SHA384")

    assert assessment.weak_markers == ()
    assert assessment.missing_forward_secrecy
    assert not assessment.missing_aead
    assert assessment.has_issue


def test_cipher_policy_reports_missing_aead_for_cbc_forward_secret_suite() -> None:
    assessment = analyze_cipher_policy("ECDHE-RSA-AES256-SHA384")

    assert assessment.weak_markers == ()
    assert not assessment.missing_forward_secrecy
    assert assessment.missing_aead
    assert assessment.has_issue


def test_cipher_policy_accepts_tls13_aead_suite() -> None:
    assessment = analyze_cipher_policy("TLS_AES_256_GCM_SHA384")

    assert assessment.weak_markers == ()
    assert not assessment.missing_forward_secrecy
    assert not assessment.missing_aead
    assert not assessment.has_issue


def test_cipher_policy_accepts_modern_tls12_suite() -> None:
    assessment = analyze_cipher_policy("ECDHE-ECDSA-CHACHA20-POLY1305")

    assert assessment.weak_markers == ()
    assert not assessment.missing_forward_secrecy
    assert not assessment.missing_aead
    assert not assessment.has_issue
