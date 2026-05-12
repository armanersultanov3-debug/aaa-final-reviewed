from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from webconf_audit.csp import (
    content_security_policy_directives,
    content_security_policy_has_reporting_endpoint,
)
from webconf_audit.external.rules._helpers import _successful_attempts_for_scheme
from webconf_audit.external.rules.script_src_missing_sri import (
    find_script_src_missing_sri,
)
from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt


def _find_x_frame_options_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.x_frame_options_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.x_frame_options_missing",
                title="X-Frame-Options header missing",
                severity="low",
                description="HTTPS endpoint responded without an X-Frame-Options header.",
                recommendation="Add an X-Frame-Options header (e.g. DENY or SAMEORIGIN) to prevent clickjacking.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="X-Frame-Options",
                ),
            )
        )

    return findings


def _find_x_frame_options_invalid(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.x_frame_options_header is None:
            continue

        normalized = attempt.x_frame_options_header.strip().upper()
        if normalized in {"DENY", "SAMEORIGIN"}:
            continue

        findings.append(
            Finding(
                rule_id="external.x_frame_options_invalid",
                title="X-Frame-Options header value invalid",
                severity="low",
                description=(
                    "HTTPS endpoint responded with an X-Frame-Options header, "
                    "but the value is not a recognized restrictive setting."
                ),
                recommendation="Use X-Frame-Options with DENY or SAMEORIGIN.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="X-Frame-Options",
                ),
            )
        )

    return findings


def _find_x_content_type_options_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.x_content_type_options_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.x_content_type_options_missing",
                title="X-Content-Type-Options header missing",
                severity="low",
                description="HTTPS endpoint responded without an X-Content-Type-Options header.",
                recommendation="Add an X-Content-Type-Options: nosniff header to prevent MIME-type sniffing.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="X-Content-Type-Options",
                ),
            )
        )

    return findings


def _find_x_content_type_options_invalid(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.x_content_type_options_header is None:
            continue

        normalized = attempt.x_content_type_options_header.strip().lower()
        if normalized == "nosniff":
            continue

        findings.append(
            Finding(
                rule_id="external.x_content_type_options_invalid",
                title="X-Content-Type-Options header value invalid",
                severity="low",
                description=(
                    "HTTPS endpoint responded with an X-Content-Type-Options header, "
                    "but the value is not nosniff."
                ),
                recommendation="Set X-Content-Type-Options to nosniff.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="X-Content-Type-Options",
                ),
            )
        )

    return findings


def _find_content_security_policy_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.content_security_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.content_security_policy_missing",
                title="Content-Security-Policy header missing",
                severity="medium",
                description="HTTPS endpoint responded without a Content-Security-Policy header.",
                recommendation="Add a Content-Security-Policy header to mitigate cross-site scripting and injection attacks.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Content-Security-Policy",
                ),
            )
        )

    return findings


def _content_security_policy_directives(header_value: str) -> dict[str, str]:
    return content_security_policy_directives(header_value)


def _content_security_policy_source_tokens(source_list: str | None) -> set[str]:
    if source_list is None:
        return set()
    return {token.lower() for token in source_list.split() if token.strip()}


def _first_non_empty_source_list(*source_lists: str | None) -> str | None:
    for source_list in source_lists:
        if source_list is not None and source_list.strip():
            return source_list
    return None


def _content_security_policy_nonce_fingerprint(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()[:12]


def _content_security_policy_effective_source_lists(
    directives: dict[str, str],
) -> tuple[str | None, ...]:
    return (
        _first_non_empty_source_list(
            directives.get("script-src"),
            directives.get("default-src"),
        ),
        _first_non_empty_source_list(
            directives.get("script-src-elem"),
            directives.get("script-src"),
            directives.get("default-src"),
        ),
        _first_non_empty_source_list(
            directives.get("script-src-attr"),
            directives.get("script-src"),
            directives.get("default-src"),
        ),
        _first_non_empty_source_list(
            directives.get("style-src"),
            directives.get("default-src"),
        ),
        _first_non_empty_source_list(
            directives.get("style-src-elem"),
            directives.get("style-src"),
            directives.get("default-src"),
        ),
        _first_non_empty_source_list(
            directives.get("style-src-attr"),
            directives.get("style-src"),
            directives.get("default-src"),
        ),
    )


def _content_security_policy_nonce_tokens(header_value: str | None) -> set[str]:
    if header_value is None:
        return set()

    directives = _content_security_policy_directives(header_value)
    tokens: set[str] = set()
    source_lists = _content_security_policy_effective_source_lists(directives)
    for source_list in source_lists:
        if source_list is None:
            continue
        for token in source_list.split():
            stripped = token.strip()
            if stripped.startswith("'nonce-") and stripped.endswith("'") and len(stripped) > 8:
                tokens.add(stripped)
    return tokens


def _content_security_policy_source_list_is_none(source_list: str | None) -> bool:
    return _content_security_policy_source_tokens(source_list) == {"'none'"}


def _inline_script_count(attempt: "ProbeAttempt") -> int | None:
    if attempt.html_recon is None:
        return None
    return len(attempt.html_recon.inline_scripts)


def _html_inline_script_nonce_tokens(attempt: "ProbeAttempt") -> set[str]:
    if attempt.html_recon is None:
        return set()
    return {
        f"'nonce-{script.nonce}'"
        for script in attempt.html_recon.inline_scripts
        if script.nonce is not None
    }


def _content_security_policy_base_uri_is_restricted(source_list: str | None) -> bool:
    tokens = _content_security_policy_source_tokens(source_list)
    return tokens in ({"'none'"}, {"'self'"})


def _find_content_security_policy_missing_frame_ancestors(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.content_security_policy_header is None:
            continue

        frame_ancestors = _content_security_policy_directives(
            attempt.content_security_policy_header
        ).get("frame-ancestors")
        if frame_ancestors:
            continue

        findings.append(
            Finding(
                rule_id="external.content_security_policy_missing_frame_ancestors",
                title="Content-Security-Policy missing frame-ancestors",
                severity="low",
                description=(
                    "HTTPS endpoint returned a Content-Security-Policy header "
                    "without a frame-ancestors directive, so embedding policy is "
                    "not controlled by CSP."
                ),
                recommendation=(
                    "Add a frame-ancestors directive such as 'none' or 'self' "
                    "to the Content-Security-Policy."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Content-Security-Policy: {attempt.content_security_policy_header}",
                ),
            )
        )

    return findings


def _find_content_security_policy_object_src_not_none(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.content_security_policy_header is None:
            continue

        directives = _content_security_policy_directives(
            attempt.content_security_policy_header
        )
        object_src = directives.get("object-src")
        effective_object_src = (
            object_src if object_src is not None else directives.get("default-src")
        )
        if _content_security_policy_source_list_is_none(effective_object_src):
            continue

        findings.append(
            Finding(
                rule_id="external.content_security_policy_object_src_not_none",
                title="Content-Security-Policy object-src is not restricted",
                severity="low",
                description=(
                    "HTTPS endpoint returned a Content-Security-Policy header "
                    "without an effective object-src 'none' policy, so legacy "
                    "plugin-style embeddings are not explicitly blocked."
                ),
                recommendation=(
                    "Set object-src 'none' in the Content-Security-Policy, or "
                    "use default-src 'none' when object-src is omitted."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Content-Security-Policy: {attempt.content_security_policy_header}",
                ),
            )
        )

    return findings


def _find_content_security_policy_base_uri_not_restricted(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.content_security_policy_header is None:
            continue

        base_uri = _content_security_policy_directives(
            attempt.content_security_policy_header
        ).get("base-uri")
        if _content_security_policy_base_uri_is_restricted(base_uri):
            continue

        findings.append(
            Finding(
                rule_id="external.content_security_policy_base_uri_not_restricted",
                title="Content-Security-Policy base-uri is not restricted",
                severity="low",
                description=(
                    "HTTPS endpoint returned a Content-Security-Policy header "
                    "without a restricted base-uri directive, so injected base "
                    "elements may alter relative URL resolution."
                ),
                recommendation=(
                    "Set base-uri 'none' or base-uri 'self' in the "
                    "Content-Security-Policy."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Content-Security-Policy: {attempt.content_security_policy_header}",
                ),
            )
        )

    return findings


def _find_content_security_policy_missing_reporting_endpoint(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.content_security_policy_header is None:
            continue
        if content_security_policy_has_reporting_endpoint(
            attempt.content_security_policy_header
        ):
            continue

        findings.append(
            Finding(
                rule_id="external.content_security_policy_missing_reporting_endpoint",
                title="Content-Security-Policy missing reporting endpoint",
                severity="low",
                description=(
                    "HTTPS endpoint returned a Content-Security-Policy header "
                    "without a report-uri or report-to directive, so policy "
                    "violations are not reported."
                ),
                recommendation=(
                    "Add a CSP report-to or report-uri directive pointing at a "
                    "controlled reporting endpoint."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Content-Security-Policy: {attempt.content_security_policy_header}",
                ),
            )
        )

    return findings


def _find_content_security_policy_unsafe_inline(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.content_security_policy_header is None:
            continue

        if "'unsafe-inline'" not in attempt.content_security_policy_header.lower():
            continue

        inline_script_count = _inline_script_count(attempt)
        severity = "info" if inline_script_count == 0 else "medium"
        if inline_script_count == 0:
            description = (
                "The Content-Security-Policy header contains 'unsafe-inline', "
                "but the parsed HTML response body did not contain inline "
                "<script> blocks."
            )
        else:
            description = (
                "The Content-Security-Policy header contains 'unsafe-inline', "
                "which permits inline scripts or styles and weakens XSS protection."
            )

        findings.append(
            Finding(
                rule_id="external.content_security_policy_unsafe_inline",
                title="Content-Security-Policy allows unsafe-inline",
                severity=severity,
                description=description,
                recommendation=(
                    "Remove 'unsafe-inline' from the Content-Security-Policy and use "
                    "nonce-based or hash-based allowlisting for inline scripts."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Content-Security-Policy: {attempt.content_security_policy_header}",
                ),
                metadata={"inline_script_count": inline_script_count},
            )
        )

    return findings


def _find_content_security_policy_unsafe_eval(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.content_security_policy_header is None:
            continue

        if "'unsafe-eval'" not in attempt.content_security_policy_header.lower():
            continue

        findings.append(
            Finding(
                rule_id="external.content_security_policy_unsafe_eval",
                title="Content-Security-Policy allows unsafe-eval",
                severity="medium",
                description=(
                    "The Content-Security-Policy header contains 'unsafe-eval', "
                    "which permits dynamic code execution via eval() and weakens "
                    "XSS protection."
                ),
                recommendation=(
                    "Remove 'unsafe-eval' from the Content-Security-Policy and "
                    "refactor application code to avoid eval()."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Content-Security-Policy: {attempt.content_security_policy_header}",
                ),
            )
        )

    return findings


def _find_content_security_policy_nonce_reused(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []
    attempts_by_nonce: dict[str, list["ProbeAttempt"]] = {}
    corroborated_attempts_by_nonce: dict[str, list["ProbeAttempt"]] = {}

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        nonces = _content_security_policy_nonce_tokens(
            attempt.content_security_policy_header
        )
        inline_nonces = _html_inline_script_nonce_tokens(attempt)
        for nonce in sorted(nonces):
            attempts_by_nonce.setdefault(nonce, []).append(attempt)
            if nonce in inline_nonces:
                corroborated_attempts_by_nonce.setdefault(nonce, []).append(attempt)

    for nonce in sorted(
        attempts_by_nonce,
        key=_content_security_policy_nonce_fingerprint,
    ):
        attempts = attempts_by_nonce[nonce]
        if len(attempts) < 2:
            continue
        nonce_fingerprint = _content_security_policy_nonce_fingerprint(nonce)
        observed_targets = ", ".join(attempt.target.url for attempt in attempts[:3])
        if len(attempts) > 3:
            observed_targets += ", ..."
        corroborated_attempts = corroborated_attempts_by_nonce.get(nonce, [])
        corroboration_note = ""
        corroboration_details = ""
        if corroborated_attempts:
            corroboration_note = (
                " Parsed HTML responses also contained inline script tags using "
                f"that nonce on {len(corroborated_attempts)} response(s)."
            )
            corroborated_targets = ", ".join(
                attempt.target.url for attempt in corroborated_attempts[:3]
            )
            if len(corroborated_attempts) > 3:
                corroborated_targets += ", ..."
            corroboration_details = (
                " Inline script nonce observed on: "
                f"{corroborated_targets}"
            )
        findings.append(
            Finding(
                rule_id="external.content_security_policy_nonce_reused",
                title="Content-Security-Policy nonce reused across responses",
                severity="medium",
                description=(
                    "HTTPS responses reused the same Content-Security-Policy "
                    f"nonce token (sha256:{nonce_fingerprint}). Nonce-based "
                    "allowlists should be "
                    f"unpredictable and unique per response.{corroboration_note}"
                ),
                recommendation=(
                    "Generate a fresh CSP nonce for every response, or use "
                    "hash-based allowlisting for static inline assets."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempts[0].target.url,
                    details=(
                        "Observed reused CSP nonce "
                        f"(sha256:{nonce_fingerprint}) on: {observed_targets}"
                        f"{corroboration_details}"
                    ),
                ),
                metadata={
                    "corroborated_inline_response_count": len(corroborated_attempts),
                },
            )
        )

    return findings


def _find_referrer_policy_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.referrer_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.referrer_policy_missing",
                title="Referrer-Policy header missing",
                severity="info",
                description="HTTPS endpoint responded without a Referrer-Policy header.",
                recommendation="Add a Referrer-Policy header to control referrer information leakage.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Referrer-Policy",
                ),
            )
        )

    return findings


def _find_referrer_policy_unsafe(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.referrer_policy_header is None:
            continue

        normalized = attempt.referrer_policy_header.strip().lower()
        if normalized != "unsafe-url":
            continue

        findings.append(
            Finding(
                rule_id="external.referrer_policy_unsafe",
                title="Unsafe Referrer-Policy value",
                severity="low",
                description=(
                    "HTTPS endpoint responded with Referrer-Policy: unsafe-url, "
                    "which may leak full referrer URLs."
                ),
                recommendation=(
                    "Use a stricter Referrer-Policy value such as "
                    "strict-origin-when-cross-origin, same-origin, or no-referrer "
                    "as appropriate."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Referrer-Policy",
                ),
            )
        )

    return findings


def _find_permissions_policy_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.permissions_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.permissions_policy_missing",
                title="Permissions-Policy header missing",
                severity="info",
                description="HTTPS endpoint responded without a Permissions-Policy header.",
                recommendation="Add a Permissions-Policy header to restrict browser feature access.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Permissions-Policy",
                ),
            )
        )

    return findings


def _find_coep_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.cross_origin_embedder_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.coep_missing",
                title="Cross-Origin-Embedder-Policy header missing",
                severity="info",
                description=(
                    "HTTPS endpoint responded without a "
                    "Cross-Origin-Embedder-Policy header."
                ),
                recommendation=(
                    "Add a Cross-Origin-Embedder-Policy header if the "
                    "application should enforce stronger cross-origin "
                    "embedding isolation."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Cross-Origin-Embedder-Policy",
                ),
            )
        )

    return findings


def _find_coop_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.cross_origin_opener_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.coop_missing",
                title="Cross-Origin-Opener-Policy header missing",
                severity="info",
                description=(
                    "HTTPS endpoint responded without a "
                    "Cross-Origin-Opener-Policy header."
                ),
                recommendation=(
                    "Add a Cross-Origin-Opener-Policy header if the "
                    "application should isolate its browsing context from "
                    "cross-origin documents."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Cross-Origin-Opener-Policy",
                ),
            )
        )

    return findings


def _find_corp_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.cross_origin_resource_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.corp_missing",
                title="Cross-Origin-Resource-Policy header missing",
                severity="info",
                description=(
                    "HTTPS endpoint responded without a "
                    "Cross-Origin-Resource-Policy header."
                ),
                recommendation=(
                    "Add a Cross-Origin-Resource-Policy header if the "
                    "application should restrict how its resources are loaded "
                    "cross-origin."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Cross-Origin-Resource-Policy",
                ),
            )
        )

    return findings


def collect_header_findings(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_find_x_frame_options_missing(probe_attempts))
    findings.extend(_find_x_frame_options_invalid(probe_attempts))
    findings.extend(_find_x_content_type_options_missing(probe_attempts))
    findings.extend(_find_x_content_type_options_invalid(probe_attempts))
    findings.extend(_find_content_security_policy_missing(probe_attempts))
    findings.extend(_find_content_security_policy_missing_frame_ancestors(probe_attempts))
    findings.extend(_find_content_security_policy_object_src_not_none(probe_attempts))
    findings.extend(_find_content_security_policy_base_uri_not_restricted(probe_attempts))
    findings.extend(_find_content_security_policy_missing_reporting_endpoint(probe_attempts))
    findings.extend(_find_content_security_policy_unsafe_inline(probe_attempts))
    findings.extend(_find_content_security_policy_unsafe_eval(probe_attempts))
    findings.extend(find_script_src_missing_sri(probe_attempts))
    findings.extend(_find_content_security_policy_nonce_reused(probe_attempts))
    findings.extend(_find_referrer_policy_missing(probe_attempts))
    findings.extend(_find_referrer_policy_unsafe(probe_attempts))
    findings.extend(_find_permissions_policy_missing(probe_attempts))
    findings.extend(_find_coep_missing(probe_attempts))
    findings.extend(_find_coop_missing(probe_attempts))
    findings.extend(_find_corp_missing(probe_attempts))
    return findings


__all__ = [
    "collect_header_findings",
]
