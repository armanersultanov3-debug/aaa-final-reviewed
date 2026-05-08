"""Tests for standards metadata helpers."""

from __future__ import annotations

import pytest

from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021, rfc


def test_cwe_uses_canonical_reference_and_url() -> None:
    ref = cwe(79)

    assert ref.standard == "CWE"
    assert ref.reference == "CWE-79"
    assert ref.url == "https://cwe.mitre.org/data/definitions/79.html"


def test_cwe_propagates_coverage_and_note() -> None:
    ref = cwe(327, coverage="partial", note="TLS-only signal.")

    assert ref.coverage == "partial"
    assert ref.note == "TLS-only signal."


@pytest.mark.parametrize("cwe_id", [0, -1, True])
def test_cwe_rejects_invalid_ids(cwe_id: int) -> None:
    with pytest.raises(ValueError, match="Unsupported CWE id"):
        cwe(cwe_id)


def test_owasp_top10_2021_rejects_unknown_category() -> None:
    with pytest.raises(ValueError, match="Unsupported OWASP Top 10 2021 category"):
        owasp_top10_2021("A99:2021")


def test_owasp_top10_2021_accepts_all_categories() -> None:
    categories = [
        "A01:2021",
        "A02:2021",
        "A03:2021",
        "A04:2021",
        "A05:2021",
        "A06:2021",
        "A07:2021",
        "A08:2021",
        "A09:2021",
        "A10:2021",
    ]

    refs = [owasp_top10_2021(category) for category in categories]

    assert [ref.reference for ref in refs] == categories
    assert all(ref.url for ref in refs)


def test_owasp_top10_2021_uses_known_category_url() -> None:
    ref = owasp_top10_2021("A10:2021")

    assert ref.standard == "OWASP Top 10"
    assert ref.reference == "A10:2021"
    assert ref.url == "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"


def test_asvs_5_uses_canonical_reference_and_url() -> None:
    ref = asvs_5("1.1.1")

    assert ref.standard == "OWASP ASVS"
    assert ref.reference == "v5.0.0-1.1.1"
    assert ref.url == "https://owasp.org/www-project-application-security-verification-standard/"


def test_asvs_5_strips_requirement_and_propagates_coverage_and_note() -> None:
    ref = asvs_5(" 12.1.1 ", coverage="related", note="Protocol policy context.")

    assert ref.reference == "v5.0.0-12.1.1"
    assert ref.coverage == "related"
    assert ref.note == "Protocol policy context."


@pytest.mark.parametrize("requirement", ["", "   "])
def test_asvs_5_rejects_empty_requirement(requirement: str) -> None:
    with pytest.raises(ValueError, match="requirement must be a non-empty string"):
        asvs_5(requirement)


def test_rfc_uses_canonical_reference_and_url() -> None:
    ref = rfc(8996)

    assert ref.standard == "IETF RFC"
    assert ref.reference == "RFC 8996"
    assert ref.url == "https://datatracker.ietf.org/doc/html/rfc8996"


def test_rfc_accepts_section_and_propagates_metadata() -> None:
    ref = rfc(
        8996,
        section="1",
        coverage="partial",
        note="TLS 1.0 and 1.1 are deprecated.",
    )

    assert ref.reference == "RFC 8996 §1"
    assert ref.url == "https://datatracker.ietf.org/doc/html/rfc8996#section-1"
    assert ref.coverage == "partial"
    assert ref.note == "TLS 1.0 and 1.1 are deprecated."


@pytest.mark.parametrize("number", [0, -1, True])
def test_rfc_rejects_invalid_numbers(number: int) -> None:
    with pytest.raises(ValueError, match="Unsupported RFC number"):
        rfc(number)


@pytest.mark.parametrize("section", ["", "   "])
def test_rfc_rejects_empty_section(section: str) -> None:
    with pytest.raises(ValueError, match="section must be a non-empty string"):
        rfc(8996, section=section)


@pytest.mark.parametrize("section", [1, 1.5, object()])
def test_rfc_rejects_non_string_section(section: object) -> None:
    with pytest.raises(ValueError, match="section must be a non-empty string"):
        rfc(8996, section=section)  # type: ignore[arg-type]
