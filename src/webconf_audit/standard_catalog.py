"""Canonical identifiers for standards used in counted coverage claims."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal

StandardSourceId = Literal[
    "cis-nginx-3.0.0",
    "cis-apache-http-server-2.4-2.3.0",
    "cis-microsoft-iis-10-1.2.1",
    "owasp-top10-2021",
    "owasp-top10-2025",
    "owasp-asvs-5.0.0",
    "nist-sp-800-52r2",
    "pci-dss-4.0.1",
    "iso-iec-27002-2022",
]


@dataclass(frozen=True)
class StandardSourceDefinition:
    source_id: StandardSourceId
    title: str
    version: str
    authority_url: str
    standard: str
    reference_pattern: str


@dataclass(frozen=True)
class StandardItemDefinition:
    source_id: StandardSourceId
    standard: str
    reference: str
    title: str
    authoritative_url: str
    edition: str


_OWASP_TOP10_2021_TITLES = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

_OWASP_TOP10_2025_TITLES = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

_ASVS_TITLES = {
    "v5.0.0-1.1.2": "HTTP response splitting protection",
    "v5.0.0-1.3.6": "Server-side request destination validation",
    "v5.0.0-3.3.1": "Secure cookie transport and prefixes",
    "v5.0.0-3.3.2": "SameSite cookie attribute",
    "v5.0.0-3.3.3": "__Host- cookie prefix",
    "v5.0.0-3.3.4": "HttpOnly cookie attribute",
    "v5.0.0-3.3.1 / 3.3.2 / 3.3.3 / 3.3.4": (
        "Cookie transport, SameSite, prefix, and HttpOnly attributes"
    ),
    "v5.0.0-3.4.1": "HTTP Strict Transport Security",
    "v5.0.0-3.4.2": "Cross-origin resource sharing policy",
    "v5.0.0-3.4.3": "Content Security Policy quality",
    "v5.0.0-3.4.4": "Content type sniffing protection",
    "v5.0.0-3.4.5": "Referrer policy",
    "v5.0.0-3.4.6": "Framing policy",
    "v5.0.0-3.4.7": "CSP reporting",
    "v5.0.0-3.4.8": "Cross-origin opener policy",
    "v5.0.0-3.7.1": "Authenticated routes require TLS",
    "v5.0.0-11.4.1": "Cryptographic integrity validation",
    "v5.0.0-12.1.1": "Deprecated TLS protocols",
    "v5.0.0-12.1.2": "TLS cipher posture",
    "v5.0.0-12.1.4": "Certificate revocation evidence",
    "v5.0.0-12.2.1": "HTTPS without cleartext fallback",
    "v5.0.0-12.2.2": "Certificate validation",
    "v5.0.0-13.4.1": "Source-control metadata exposure",
    "v5.0.0-13.4.2": "Production debug features",
    "v5.0.0-13.4.3": "Directory listing",
    "v5.0.0-13.4.4": "TRACE method",
    "v5.0.0-13.4.5": "Documentation and monitoring endpoints",
    "v5.0.0-13.4.6": "Component and version disclosure",
    "v5.0.0-13.4.7": "Secret and configuration exposure",
}

_PCI_TITLES = {
    "Req. 2.2.1": "Configuration standards",
    "Req. 2.2.5": "Insecure services and protocols",
    "Req. 2.2.6": "System security parameters",
    "Req. 4.2.1": "Strong cryptography over public networks",
    "Req. 6.2.4": "Software engineering techniques",
    "Req. 6.4.3": "Payment-page script management",
    "Req. 8.3.1": "Authentication-factor protection",
    "Req. 8.3.2": "Cryptographic protection in transit",
    "Req. 8.3.5 / 8.3.6": "Password reset and complexity requirements",
    "Req. 8.3.5": "Password first-use and reset handling",
    "Req. 8.3.6": "Password length and composition requirements",
    "Req. 10.2.1": "Audit logging enabled",
    "Req. 10.2.2": "Audit log event details",
    "Req. 10.5": "Audit log retention and protection",
    "Req. 12": "Organizational security policies",
}

_ASVS_ROOT_URL = "https://github.com/OWASP/ASVS/tree/master/5.0/en"
_ASVS_V3_URL = (
    "https://github.com/OWASP/ASVS/blob/master/5.0/en/"
    "0x12-V3-Web-Frontend-Security.md"
)
_PCI_URL = (
    "https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/"
    "PCI-DSS-v4_0_1.pdf"
)

STANDARD_SOURCES: tuple[StandardSourceDefinition, ...] = (
    StandardSourceDefinition(
        "cis-nginx-3.0.0",
        "CIS NGINX Benchmark v3.0.0",
        "3.0.0",
        "https://www.cisecurity.org/benchmark/nginx",
        "CIS",
        r"^NGINX v3\.0\.0 §.+$",
    ),
    StandardSourceDefinition(
        "cis-apache-http-server-2.4-2.3.0",
        "CIS Apache HTTP Server 2.4 Benchmark v2.3.0",
        "2.3.0",
        "https://www.cisecurity.org/benchmark/apache_http_server",
        "CIS",
        r"^Apache HTTP Server 2\.4 v2\.3\.0 §.+$",
    ),
    StandardSourceDefinition(
        "cis-microsoft-iis-10-1.2.1",
        "CIS Microsoft IIS 10 Benchmark v1.2.1",
        "1.2.1",
        "https://www.cisecurity.org/benchmark/microsoft_iis",
        "CIS",
        r"^Microsoft IIS 10 v1\.2\.1 §.+$",
    ),
    StandardSourceDefinition(
        "owasp-top10-2021",
        "OWASP Top 10:2021",
        "2021",
        "https://owasp.org/Top10/",
        "OWASP Top 10",
        r"^A\d{2}:2021$",
    ),
    StandardSourceDefinition(
        "owasp-top10-2025",
        "OWASP Top 10:2025",
        "2025",
        "https://owasp.org/Top10/2025/",
        "OWASP Top 10",
        r"^A\d{2}:2025$",
    ),
    StandardSourceDefinition(
        "owasp-asvs-5.0.0",
        "OWASP ASVS v5.0.0",
        "5.0.0",
        _ASVS_V3_URL,
        "OWASP ASVS",
        r"^v5\.0\.0-\d+\.\d+\.\d+(?: / .+)?$",
    ),
    StandardSourceDefinition(
        "nist-sp-800-52r2",
        "NIST SP 800-52 Rev. 2",
        "Rev. 2",
        "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final",
        "NIST SP 800-52 Rev. 2",
        r"^(?:\d+(?:\.\d+)*(?: / \d+(?:\.\d+)*)?|NO PLAINTEXT FALLBACK)$",
    ),
    StandardSourceDefinition(
        "pci-dss-4.0.1",
        "PCI DSS v4.0.1",
        "4.0.1",
        _PCI_URL,
        "PCI DSS v4.0.1",
        r"^Req\. \d+(?:\.\d+)*(?: / \d+(?:\.\d+)*)?$",
    ),
    StandardSourceDefinition(
        "iso-iec-27002-2022",
        "ISO/IEC 27002:2022",
        "2022",
        "https://www.iso.org/standard/75652.html",
        "ISO/IEC 27002:2022",
        r"^\d+\.\d+$",
    ),
)


STANDARD_ITEMS: tuple[StandardItemDefinition, ...] = (
    *(
        StandardItemDefinition(
            source_id="owasp-top10-2021",
            standard="OWASP Top 10",
            reference=reference,
            title=title,
            authoritative_url="https://owasp.org/Top10/",
            edition="2021",
        )
        for reference, title in _OWASP_TOP10_2021_TITLES.items()
    ),
    *(
        StandardItemDefinition(
            source_id="owasp-top10-2025",
            standard="OWASP Top 10",
            reference=reference,
            title=title,
            authoritative_url="https://owasp.org/Top10/2025/",
            edition="2025",
        )
        for reference, title in _OWASP_TOP10_2025_TITLES.items()
    ),
    *(
        StandardItemDefinition(
            source_id="owasp-asvs-5.0.0",
            standard="OWASP ASVS",
            reference=reference,
            title=title,
            authoritative_url=(
                _ASVS_V3_URL
                if reference.startswith("v5.0.0-3.")
                else _ASVS_ROOT_URL
            ),
            edition="5.0.0",
        )
        for reference, title in _ASVS_TITLES.items()
    ),
    *(
        StandardItemDefinition(
            source_id="pci-dss-4.0.1",
            standard="PCI DSS v4.0.1",
            reference=reference,
            title=title,
            authoritative_url=_PCI_URL,
            edition="4.0.1",
        )
        for reference, title in _PCI_TITLES.items()
    ),
)


def _prefixed_references(
    prefix: str,
    references: set[str],
) -> frozenset[str]:
    return frozenset(f"{prefix}{reference}" for reference in references)


_NGINX_LEDGER_REFERENCES = _prefixed_references(
    "NGINX v3.0.0 §",
    {
        "2.4.2",
        "2.5.2",
        "2.5.4",
        "3.1",
        "3.3",
        "3.4",
        "4.1.1",
        "4.1.2",
        "4.1.5",
        "4.1.9",
        "4.1.10",
        "4.1.9 / §4.1.10",
        "4.1.12",
        "5.1.1",
        "5.1.2",
        "5.2.4",
        "5.2.5",
        "5.2.4 / §5.2.5",
        "5.3.2",
        "5.3.3",
        "5.3.2 / §5.3.3",
    },
)

_APACHE_LEDGER_SECTIONS = (
    {f"2.{index}" for index in range(1, 10)}
    | {f"4.{index}" for index in range(1, 5)}
    | {f"5.{index}" for index in range(1, 8)}
    | {f"5.{index}" for index in range(9, 19)}
    | {"6.1", "6.3", "6.6", "6.7", "7.1", "7.2"}
    | {f"7.{index}" for index in range(4, 13)}
    | {"8.3", "8.4"}
    | {f"9.{index}" for index in range(1, 7)}
    | {f"10.{index}" for index in range(1, 5)}
    | {
        "2.1-§2.9",
        "4.1-§4.2",
        "4.3-§4.4",
        "5.1-§5.3",
        "5.4-§5.6",
        "5.10-§5.13",
        "5.14-§5.15",
        "5.16-§5.18",
        "6.1 / §6.3",
        "6.6-§6.7",
        "7.1 / §7.4-§7.12",
        "9.1-§9.4",
        "9.5-§9.6",
        "10.1-§10.4",
    }
)
_APACHE_LEDGER_REFERENCES = _prefixed_references(
    "Apache HTTP Server 2.4 v2.3.0 §",
    _APACHE_LEDGER_SECTIONS,
)

_IIS_LEDGER_SECTIONS = (
    {"1.2", "1.4", "1.5", "1.6", "2.1", "2.2", "2.5", "2.6", "2.7", "2.8"}
    | {"3.1", "4.2", "4.3", "4.7", "4.8", "4.9", "4.10", "6.1", "6.2"}
    | {f"3.{index}" for index in range(7, 13)}
    | {f"7.{index}" for index in range(1, 7)}
    | {f"7.{index}" for index in range(10, 13)}
    | {
        "1.4 / §1.5 / §1.6",
        "2.1 / §2.2",
        "2.5 / §2.7 / §2.8",
        "3.1 / §3.7-§3.12",
        "4.2 / §4.3 / §4.7 / §4.9 / §4.10",
        "6.1 / §6.2",
        "7.1-§7.6 / §7.10-§7.12",
    }
)
_IIS_LEDGER_REFERENCES = _prefixed_references(
    "Microsoft IIS 10 v1.2.1 §",
    _IIS_LEDGER_SECTIONS,
)

_LEDGER_REFERENCES_BY_SOURCE: dict[str, frozenset[str]] = {
    "cis-nginx-3.0.0": _NGINX_LEDGER_REFERENCES,
    "cis-apache-http-server-2.4-2.3.0": _APACHE_LEDGER_REFERENCES,
    "cis-microsoft-iis-10-1.2.1": _IIS_LEDGER_REFERENCES,
    "nist-sp-800-52r2": frozenset(
        {
            "3.1.1",
            "3.1.2",
            "3.1.1 / 3.1.2",
            "3.3.1",
            "3.3.2",
            "3.4",
            "3.5",
            "3.6",
            "4.2",
            "4.2.4",
            "4.3",
            "NO PLAINTEXT FALLBACK",
        }
    ),
    "iso-iec-27002-2022": frozenset(
        {
            "5.15",
            "8.5",
            "8.15",
            "8.16",
            "8.18",
            "8.20",
            "8.21",
            "8.24",
            "8.26",
            "8.27",
        }
    ),
}

_ITEMS_BY_KEY = {
    (item.standard, item.reference): item
    for item in STANDARD_ITEMS
}
STANDARD_SOURCE_IDS = frozenset(source.source_id for source in STANDARD_SOURCES)
STRICT_CATALOG_STANDARDS = frozenset(item.standard for item in STANDARD_ITEMS)
_SOURCES_BY_ID = {source.source_id: source for source in STANDARD_SOURCES}


def find_standard_item(
    standard: str,
    reference: str,
) -> StandardItemDefinition | None:
    """Return the canonical definition for a strict standard/reference pair."""
    return _ITEMS_BY_KEY.get((standard, reference))


def find_standard_source(
    source_id: str,
) -> StandardSourceDefinition | None:
    """Return one counted source definition without making it globally strict."""
    return _SOURCES_BY_ID.get(source_id)  # type: ignore[arg-type]


def is_valid_ledger_reference(
    source_id: str,
    standard: str,
    reference: str,
) -> bool:
    """Validate a counted reference within its source-scoped catalog."""
    source = find_standard_source(source_id)
    if source is None or source.standard != standard:
        return False
    if re.fullmatch(source.reference_pattern, reference) is None:
        return False
    if standard in STRICT_CATALOG_STANDARDS:
        return find_standard_item(standard, reference) is not None
    return reference in _LEDGER_REFERENCES_BY_SOURCE.get(source_id, ())


__all__ = [
    "STANDARD_ITEMS",
    "STANDARD_SOURCES",
    "STANDARD_SOURCE_IDS",
    "STRICT_CATALOG_STANDARDS",
    "StandardItemDefinition",
    "StandardSourceDefinition",
    "StandardSourceId",
    "find_standard_item",
    "find_standard_source",
    "is_valid_ledger_reference",
]
