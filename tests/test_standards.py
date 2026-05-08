"""Tests for standards metadata helpers."""

from __future__ import annotations

import pytest

from webconf_audit.standards import (
    asvs_5,
    bsi_app_3_2,
    cwe,
    fstec_gis,
    nist_sp_800_53_rev5,
    owasp_top10_2021,
    pci_dss_4,
    rfc,
)


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


def test_nist_sp_800_53_rev5_uses_canonical_reference_and_url() -> None:
    ref = nist_sp_800_53_rev5("IA-2")

    assert ref.standard == "NIST SP 800-53 Rev. 5"
    assert ref.reference == "IA-2"
    assert ref.url == "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"


def test_nist_sp_800_53_rev5_strips_control_and_propagates_metadata() -> None:
    ref = nist_sp_800_53_rev5(
        " IA-5(1) ",
        coverage="partial",
        note="Authentication-factor transport only.",
    )

    assert ref.reference == "IA-5(1)"
    assert ref.coverage == "partial"
    assert ref.note == "Authentication-factor transport only."


@pytest.mark.parametrize("control", ["", "   "])
def test_nist_sp_800_53_rev5_rejects_empty_control(control: str) -> None:
    with pytest.raises(ValueError, match="control must be a non-empty string"):
        nist_sp_800_53_rev5(control)


@pytest.mark.parametrize("control", [None, 1, object()])
def test_nist_sp_800_53_rev5_rejects_non_string_control(control: object) -> None:
    with pytest.raises(ValueError, match="control must be a non-empty string"):
        nist_sp_800_53_rev5(control)  # type: ignore[arg-type]


def test_pci_dss_4_uses_canonical_reference_and_url() -> None:
    ref = pci_dss_4("8.3.1")

    assert ref.standard == "PCI DSS v4.0.1"
    assert ref.reference == "Req. 8.3.1"
    assert (
        ref.url
        == "https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf"
    )


def test_pci_dss_4_accepts_requirement_with_prefix() -> None:
    ref = pci_dss_4("Req. 4.2.1")

    assert ref.reference == "Req. 4.2.1"


@pytest.mark.parametrize("requirement", ["", "   "])
def test_pci_dss_4_rejects_empty_requirement(requirement: str) -> None:
    with pytest.raises(ValueError, match="requirement must be a non-empty string"):
        pci_dss_4(requirement)


@pytest.mark.parametrize("requirement", [None, 1, object()])
def test_pci_dss_4_rejects_non_string_requirement(requirement: object) -> None:
    with pytest.raises(ValueError, match="requirement must be a non-empty string"):
        pci_dss_4(requirement)  # type: ignore[arg-type]


def test_bsi_app_3_2_uses_canonical_reference_and_url() -> None:
    ref = bsi_app_3_2("A5")

    assert ref.standard == "BSI IT-Grundschutz"
    assert ref.reference == "APP.3.2.A5"
    assert (
        ref.url
        == "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/it-grundschutz-kompendium_node.html"
    )


def test_bsi_app_3_2_accepts_fully_qualified_requirement() -> None:
    ref = bsi_app_3_2("APP.3.2.A14", coverage="partial")

    assert ref.reference == "APP.3.2.A14"
    assert ref.coverage == "partial"


@pytest.mark.parametrize("requirement", ["", "   "])
def test_bsi_app_3_2_rejects_empty_requirement(requirement: str) -> None:
    with pytest.raises(ValueError, match="requirement must be a non-empty string"):
        bsi_app_3_2(requirement)


@pytest.mark.parametrize("requirement", [None, 1, object()])
def test_bsi_app_3_2_rejects_non_string_requirement(requirement: object) -> None:
    with pytest.raises(ValueError, match="requirement must be a non-empty string"):
        bsi_app_3_2(requirement)  # type: ignore[arg-type]


def test_fstec_gis_uses_canonical_reference_and_url() -> None:
    ref = fstec_gis("ИАФ.1")

    assert ref.standard == 'ФСТЭК "Меры защиты информации в ГИС"'
    assert ref.reference == "ИАФ.1"
    assert (
        ref.url
        == "https://fstec.ru/dokumenty/vse-dokumenty/prikazy/prikaz-fstek-rossii-ot-11-fevralya-2013-g-n-17"
    )


def test_fstec_gis_strips_measure_and_propagates_metadata() -> None:
    ref = fstec_gis(
        " ИАФ.6 ",
        coverage="partial",
        note="Transport protection signal only.",
    )

    assert ref.reference == "ИАФ.6"
    assert ref.coverage == "partial"
    assert ref.note == "Transport protection signal only."


@pytest.mark.parametrize("measure", ["", "   "])
def test_fstec_gis_rejects_empty_measure(measure: str) -> None:
    with pytest.raises(ValueError, match="measure must be a non-empty string"):
        fstec_gis(measure)


@pytest.mark.parametrize("measure", [None, 1, object()])
def test_fstec_gis_rejects_non_string_measure(measure: object) -> None:
    with pytest.raises(ValueError, match="measure must be a non-empty string"):
        fstec_gis(measure)  # type: ignore[arg-type]
