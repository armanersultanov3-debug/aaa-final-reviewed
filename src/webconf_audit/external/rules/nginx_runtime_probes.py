from __future__ import annotations

import re
from typing import TYPE_CHECKING

from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cis_nginx_v3_0_0, cwe

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt

_DEFAULT_INDEX_MARKER = "welcome to nginx!"
_NGINX_SERVER_HEADER_PATTERN = re.compile(r"(?i)\b(?:nginx|openresty)(?:/|\b)")


@rule(
    rule_id="external.nginx.redirect_target_unexpected",
    title="Nginx HTTP endpoint serves content instead of redirecting",
    severity="low",
    description=(
        "A plaintext HTTP probe served a response body from an nginx-family "
        "endpoint instead of redirecting the client away from HTTP."
    ),
    recommendation=(
        "Redirect plaintext HTTP requests to HTTPS or another intended scheme "
        "before serving application content."
    ),
    category="external",
    input_kind="probe",
    condition="nginx",
    standards=(
        cis_nginx_v3_0_0(
            "4.1.1",
            coverage="partial",
            note=(
                "Runtime evidence; primary CIS reference at "
                "nginx.missing_http_to_https_redirect."
            ),
        ),
    ),
    order=676,
)
def find_nginx_redirect_target_unexpected(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in probe_attempts:
        if not _attempt_has_body_on_plain_http(attempt):
            continue
        if not _attempt_has_nginx_fingerprint(attempt):
            continue

        findings.append(
            Finding(
                rule_id="external.nginx.redirect_target_unexpected",
                title="Nginx HTTP endpoint serves content instead of redirecting",
                severity="low",
                description=(
                    "The plaintext HTTP root endpoint returned a 200 response "
                    "with body content instead of redirecting the client to "
                    "HTTPS or another intended scheme."
                ),
                recommendation=(
                    "Configure nginx to redirect plaintext HTTP requests "
                    "before serving content from the root endpoint."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=attempt.target.url,
                    details=f"status: {attempt.status_code}",
                ),
            )
        )

    return findings


@rule(
    rule_id="external.nginx.default_index_page_body",
    title="Default nginx index page body exposed",
    severity="low",
    description=(
        'The externally visible root response body contains the default nginx '
        'welcome marker "Welcome to nginx!".'
    ),
    recommendation=(
        "Replace the default nginx index page with the intended site content "
        "or a hardened maintenance page."
    ),
    category="external",
    input_kind="probe",
    condition="nginx",
    standards=(
        cis_nginx_v3_0_0("2.5.2", coverage="partial"),
        cwe(200),
    ),
    order=677,
)
def find_nginx_default_index_page_body(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in probe_attempts:
        if not _attempt_has_root_body(attempt):
            continue
        if not _body_has_default_index_marker(attempt.body_snippet):
            continue
        if not _attempt_has_nginx_fingerprint(attempt):
            continue

        findings.append(
            Finding(
                rule_id="external.nginx.default_index_page_body",
                title="Default nginx index page body exposed",
                severity="low",
                description=(
                    'The root response body contains the default nginx marker '
                    '"Welcome to nginx!", which discloses placeholder content '
                    "to external clients."
                ),
                recommendation=(
                    "Replace the default nginx index page with application "
                    "content or a hardened maintenance page."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=attempt.target.url,
                    details='body marker: "Welcome to nginx!"',
                ),
            )
        )

    return findings


def _attempt_has_body_on_plain_http(attempt: "ProbeAttempt") -> bool:
    return (
        attempt.has_http_response
        and attempt.target.scheme == "http"
        and attempt.target.path == "/"
        and attempt.status_code == 200
        and attempt.body_snippet is not None
    )


def _attempt_has_root_body(attempt: "ProbeAttempt") -> bool:
    return (
        attempt.has_http_response
        and attempt.target.path == "/"
        and attempt.status_code == 200
        and attempt.body_snippet is not None
    )


def _attempt_has_nginx_fingerprint(attempt: "ProbeAttempt") -> bool:
    if attempt.server_header is not None:
        return _NGINX_SERVER_HEADER_PATTERN.search(attempt.server_header) is not None
    return _body_has_default_index_marker(attempt.body_snippet)


def _body_has_default_index_marker(body_snippet: str | None) -> bool:
    return body_snippet is not None and _DEFAULT_INDEX_MARKER in body_snippet.lower()


__all__ = [
    "find_nginx_default_index_page_body",
    "find_nginx_redirect_target_unexpected",
]
