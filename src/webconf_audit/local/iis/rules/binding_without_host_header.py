"""iis.binding_without_host_header -- Binding without host header."""

from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISChildElement, IISConfigDocument
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule

RULE_ID = "iis.binding_without_host_header"

_HTTP_BINDING_PROTOCOLS = frozenset({"http", "https"})


@rule(
    rule_id=RULE_ID,
    title="Binding without host header",
    severity="low",
    description="An IIS HTTP or HTTPS binding does not set a host name.",
    recommendation=(
        "Set a host name on named IIS HTTP/HTTPS site bindings and reserve "
        "hostless bindings for intentional catch-all sites."
    ),
    category="local",
    server_type="iis",
    input_kind="ast",
    standards=(
        StandardReference(
            standard="CIS",
            reference="Microsoft IIS 10 v1.2.1 §1.2",
            url="https://www.cisecurity.org/benchmark/microsoft_iis",
            coverage="partial",
            note=(
                "Detects HTTP/HTTPS bindings that omit a host name; "
                "intentional catch-all binding policy remains operator-specific."
            ),
        ),
    ),
    order=520,
)
def find_binding_without_host_header(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    del effective_config
    findings: list[Finding] = []

    for section in doc.sections:
        if section.tag != "bindings":
            continue
        for child in section.children:
            if _is_http_binding_without_host(child):
                findings.append(_finding(child))

    return findings


def _is_http_binding_without_host(binding: IISChildElement) -> bool:
    if binding.tag.lower() != "binding":
        return False
    protocol = binding.attributes.get("protocol", "").strip().lower()
    if protocol not in _HTTP_BINDING_PROTOCOLS:
        return False
    return not _binding_host(binding.attributes.get("bindingInformation", ""))


def _binding_host(binding_information: str) -> str:
    stripped = binding_information.strip()
    if stripped.count(":") < 2:
        return ""
    return stripped.rsplit(":", 1)[1].strip()


def _finding(binding: IISChildElement) -> Finding:
    binding_info = binding.attributes.get("bindingInformation", "")
    protocol = binding.attributes.get("protocol", "").strip().lower()
    return Finding(
        rule_id=RULE_ID,
        title="Binding without host header",
        severity="low",
        description=(
            f'IIS {protocol.upper()} binding "{binding_info}" does not set a '
            "host name, so the site can answer unexpected Host headers on "
            "that IP and port."
        ),
        recommendation=(
            "Set the host-name field in bindingInformation "
            '(for example, "*:443:www.example.com") or document the binding '
            "as an intentional catch-all site."
        ),
        location=_binding_location(binding),
    )


def _binding_location(binding: IISChildElement) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="xml",
        file_path=binding.source.file_path,
        xml_path=binding.source.xml_path,
    )
