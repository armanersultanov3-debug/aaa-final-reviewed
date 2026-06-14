from __future__ import annotations

from webconf_audit.csp import (
    CspDisposition,
    CspTokenKind,
    content_security_policy_directives,
    parse_csp_header_value,
)


def test_parse_csp_header_value_preserves_policy_list_boundaries() -> None:
    parsed = parse_csp_header_value(
        "default-src 'self'; script-src 'unsafe-inline', object-src 'none'",
        disposition=CspDisposition.ENFORCE,
    )

    assert len(parsed.policies) == 2
    assert parsed.policies[0].first_directive("default-src") is not None
    assert parsed.policies[1].first_directive("object-src") is not None


def test_parse_csp_header_value_preserves_duplicate_directives() -> None:
    parsed = parse_csp_header_value(
        "script-src 'self'; script-src 'unsafe-inline'",
        disposition=CspDisposition.ENFORCE,
    )

    directives = parsed.policies[0].directives
    assert len(directives) == 2
    assert directives[0].effective is True
    assert directives[1].effective is False
    assert directives[1].duplicate_of == 0
    assert content_security_policy_directives(
        "script-src 'self'; script-src 'unsafe-inline'"
    ) == {"script-src": "'self'"}


def test_parse_csp_header_value_classifies_nonce_and_hash_tokens() -> None:
    parsed = parse_csp_header_value(
        "script-src 'nonce-$csp_nonce' sha256-QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE= https:",
        disposition=CspDisposition.ENFORCE,
    )

    tokens = parsed.policies[0].first_directive("script-src").tokens
    assert [token.kind for token in tokens] == [
        CspTokenKind.NONCE,
        CspTokenKind.HASH,
        CspTokenKind.SCHEME,
    ]


def test_parse_csp_header_value_classifies_quoted_hash_tokens() -> None:
    parsed = parse_csp_header_value(
        "script-src 'sha256-QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE='",
        disposition=CspDisposition.ENFORCE,
    )

    token = parsed.policies[0].first_directive("script-src").tokens[0]
    assert token.kind == CspTokenKind.HASH
    assert token.valid is True
    assert token.normalized == "sha256-QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="


def test_parse_csp_header_value_rejects_invalid_static_nonce_base64() -> None:
    parsed = parse_csp_header_value(
        "script-src 'nonce-not_base64!'",
        disposition=CspDisposition.ENFORCE,
    )

    token = parsed.policies[0].first_directive("script-src").tokens[0]
    assert token.kind == CspTokenKind.NONCE
    assert token.valid is False
    assert "invalid-nonce" in {issue.code for issue in parsed.issues}
