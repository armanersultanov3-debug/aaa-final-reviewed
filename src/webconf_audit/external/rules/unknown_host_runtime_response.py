from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cis_nginx_v3_0_0, cwe

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt


@rule(
    rule_id="external.unknown_host_runtime_response",
    title="Unknown Host accepted with baseline response",
    severity="medium",
    description=(
        "A synthetic unknown Host header was accepted at runtime and returned "
        "the same body as the baseline root response."
    ),
    recommendation=(
        "Configure a dedicated catch-all virtual host or default server that "
        "rejects unexpected Host values with a clear 4xx/444-style response."
    ),
    category="external",
    input_kind="probe",
    standards=(
        cis_nginx_v3_0_0(
            "2.4.2",
            coverage="partial",
            note=(
                "Runtime evidence of unknown-Host acceptance; primary config "
                "check at nginx.default_server_not_rejecting_unknown_hosts."
            ),
        ),
        asvs_5("13.4.5"),
        cwe(346),
    ),
    order=719,
)
def find_unknown_host_runtime_response(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []
    seen_targets: set[str] = set()

    for attempt in probe_attempts:
        probe = attempt.unknown_host_probe
        if probe is None:
            continue
        if probe.target.url in seen_targets:
            continue
        seen_targets.add(probe.target.url)
        if probe.disposition != "accepted_same_content":
            continue

        baseline = probe.baseline_response
        unknown = probe.unknown_host_response
        findings.append(
            Finding(
                rule_id="external.unknown_host_runtime_response",
                title="Unknown Host accepted with baseline response",
                severity="medium",
                description=(
                    "The endpoint returned HTTP 200 for a synthetic unknown "
                    f"Host value ({probe.host_header}) and served the same "
                    "response body as the baseline root page. This indicates "
                    "the runtime listener does not distinguish unexpected Host "
                    "names."
                ),
                recommendation=(
                    "Add a default or catch-all virtual host that rejects "
                    "unexpected Host values before application content is served."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.target.url,
                    details=(
                        f"host_header: {probe.host_header}, "
                        f"baseline_status: {baseline.status_code}, "
                        f"probe_status: {unknown.status_code}, "
                        f"body_sha256: {unknown.body_sha256}"
                    ),
                ),
                metadata={
                    "host_header": probe.host_header,
                    "baseline_response": {
                        "status_code": baseline.status_code,
                        "body_sha256": baseline.body_sha256,
                        "body_size": baseline.body_size,
                        "server_header": baseline.server_header,
                        "content_type_header": baseline.content_type_header,
                        "location_header": baseline.location_header,
                    },
                    "unknown_host_response": {
                        "status_code": unknown.status_code,
                        "body_sha256": unknown.body_sha256,
                        "body_size": unknown.body_size,
                        "server_header": unknown.server_header,
                        "content_type_header": unknown.content_type_header,
                        "location_header": unknown.location_header,
                    },
                },
            )
        )

    return findings


__all__ = ["find_unknown_host_runtime_response"]
