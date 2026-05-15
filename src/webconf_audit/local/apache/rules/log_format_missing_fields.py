"""apache.log_format_missing_fields -- LogFormat misses detailed audit fields."""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._log_policy_utils import (
    ResolvedCustomLogFormat,
    iter_effective_custom_log_formats,
)
from webconf_audit.local.apache.rules.server_directive_utils import (
    virtualhost_label,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cwe, owasp_top10_2021

RULE_ID = "apache.log_format_missing_fields"

_REQUIRED_FIELD_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("client address", ("%h", "%a")),
    ("remote user", ("%u",)),
    ("timestamp", ("%t", "%{", "}t")),
    ("request line", ("%r",)),
    ("status", ("%>s", "%s")),
    ("response size", ("%b", "%O")),
    ("referer", ("%{referer}i",)),
    ("user-agent", ("%{user-agent}i", "%{user_agent}i")),
    ("request ID", ("%{x-request-id}i", "%{x-correlation-id}i", "%L")),
    ("forwarded chain", ("%{x-forwarded-for}i",)),
    ("request timing", ("%d",)),
)
_TLS_FIELD_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("TLS protocol/cipher", ("%{ssl_protocol}x", "%{ssl_cipher}x")),
)


@rule(
    rule_id=RULE_ID,
    title="LogFormat misses detailed audit fields",
    severity="low",
    description="Apache LogFormat is present but misses recommended audit fields.",
    recommendation=(
        "Include client address, remote user, timestamp, request, status, "
        "response size, referer, user-agent, request ID, forwarded chain, "
        "request timing, and TLS protocol/cipher fields where applicable in "
        "access logs."
    ),
    category="local",
    server_type="apache",
    standards=(
        cwe(778),
        owasp_top10_2021("A09:2021"),
    ),
    order=348,
)
def find_log_format_missing_fields(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    affected_scopes: set[int | str] = set()

    for resolved in iter_effective_custom_log_formats(config_ast):
        if resolved.format_text is None:
            continue

        missing_fields = _missing_fields(
            resolved.format_text.lower(),
            tls_enabled=resolved.tls_enabled,
        )
        if not missing_fields:
            continue

        scope_key = id(resolved.context) if resolved.context is not None else "global"
        if scope_key in affected_scopes:
            continue
        affected_scopes.add(scope_key)
        findings.append(_build_finding(resolved, missing_fields))

    return findings


def _build_finding(
    resolved: ResolvedCustomLogFormat,
    missing_fields: list[str],
) -> Finding:
    metadata = {"format_name": resolved.format_name}
    if resolved.context is not None:
        metadata["scope_name"] = virtualhost_label(resolved.context)

    return Finding(
        rule_id=RULE_ID,
        title="LogFormat misses detailed audit fields",
        severity="low",
        description=(
            "Apache LogFormat misses recommended audit fields: "
            + ", ".join(missing_fields)
        ),
        recommendation="Add the missing fields to the LogFormat used by CustomLog.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=resolved.custom_log.source.file_path,
            line=resolved.custom_log.source.line,
        ),
        metadata=metadata,
    )


def _missing_fields(format_text: str, *, tls_enabled: bool) -> list[str]:
    missing: list[str] = []
    field_groups = list(_REQUIRED_FIELD_GROUPS)
    if tls_enabled:
        field_groups.extend(_TLS_FIELD_GROUPS)

    for label, markers in field_groups:
        if label == "timestamp":
            if "%t" in format_text or ("%{" in format_text and "}t" in format_text):
                continue
            missing.append(label)
            continue

        if not any(marker in format_text for marker in markers):
            missing.append(label)
    return missing


__all__ = ["find_log_format_missing_fields"]
