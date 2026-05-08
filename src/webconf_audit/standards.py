"""Helpers for attaching standards references to rule metadata."""

from __future__ import annotations

from webconf_audit.rule_registry import StandardCoverage, StandardReference

_OWASP_TOP10_2021_URLS = {
    "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03:2021": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04:2021": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06:2021": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08:2021": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09:2021": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10:2021": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}


def cwe(
    cwe_id: int,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    if isinstance(cwe_id, bool) or not isinstance(cwe_id, int) or cwe_id < 1:
        raise ValueError(f"Unsupported CWE id: {cwe_id}. Expected a positive integer.")
    return StandardReference(
        standard="CWE",
        reference=f"CWE-{cwe_id}",
        url=f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
        coverage=coverage,
        note=note,
    )


def owasp_top10_2021(
    category: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    if category not in _OWASP_TOP10_2021_URLS:
        valid_categories = ", ".join(sorted(_OWASP_TOP10_2021_URLS))
        raise ValueError(
            f"Unsupported OWASP Top 10 2021 category: {category}. "
            f"Expected one of: {valid_categories}."
        )
    return StandardReference(
        standard="OWASP Top 10",
        reference=category,
        url=_OWASP_TOP10_2021_URLS[category],
        coverage=coverage,
        note=note,
    )


def asvs_5(
    requirement: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    normalized_requirement = requirement.strip()
    if not normalized_requirement:
        raise ValueError("asvs_5: requirement must be a non-empty string.")
    return StandardReference(
        standard="OWASP ASVS",
        reference=f"v5.0.0-{normalized_requirement}",
        url="https://owasp.org/www-project-application-security-verification-standard/",
        coverage=coverage,
        note=note,
    )


def rfc(
    number: int,
    *,
    section: str | None = None,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise ValueError(f"Unsupported RFC number: {number}. Expected a positive integer.")

    normalized_section = section.strip() if section is not None else None
    if normalized_section == "":
        raise ValueError("rfc: section must be a non-empty string when provided.")

    reference = f"RFC {number}"
    url = f"https://datatracker.ietf.org/doc/html/rfc{number}"
    if normalized_section is not None:
        reference = f"{reference} §{normalized_section}"
        url = f"{url}#section-{normalized_section}"

    return StandardReference(
        standard="IETF RFC",
        reference=reference,
        url=url,
        coverage=coverage,
        note=note,
    )


__all__ = ["asvs_5", "cwe", "owasp_top10_2021", "rfc"]
