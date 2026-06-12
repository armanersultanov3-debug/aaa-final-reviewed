"""Canonical identifiers for standards used in counted coverage claims."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

StandardSourceId = Literal[
    "owasp-top10-2021",
    "owasp-top10-2025",
    "owasp-asvs-5.0.0",
    "pci-dss-4.0.1",
]


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
    "Req. 10.2.1": "Audit logging enabled",
    "Req. 10.2.2": "Audit log event details",
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

_ITEMS_BY_KEY = {
    (item.standard, item.reference): item
    for item in STANDARD_ITEMS
}
STANDARD_SOURCE_IDS = frozenset(item.source_id for item in STANDARD_ITEMS)
STRICT_CATALOG_STANDARDS = frozenset(item.standard for item in STANDARD_ITEMS)


def find_standard_item(
    standard: str,
    reference: str,
) -> StandardItemDefinition | None:
    """Return the canonical definition for a strict standard/reference pair."""
    return _ITEMS_BY_KEY.get((standard, reference))


__all__ = [
    "STANDARD_ITEMS",
    "STANDARD_SOURCE_IDS",
    "STRICT_CATALOG_STANDARDS",
    "StandardItemDefinition",
    "StandardSourceId",
    "find_standard_item",
]
