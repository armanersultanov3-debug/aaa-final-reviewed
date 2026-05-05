from __future__ import annotations

from webconf_audit.hsts_policy import hsts_policy_reason
from webconf_audit.local.apache.parser import ApacheConfigAst, ApacheSourceSpan
from webconf_audit.local.apache.rules._tls_policy_utils import iter_tls_scopes
from webconf_audit.local.apache.rules.security_header_utils import (
    ApacheHeaderScope,
    ApacheHeaderSetting,
    iter_effective_header_scopes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

MISSING_RULE_ID = "apache.missing_hsts_header"
UNSAFE_RULE_ID = "apache.hsts_header_unsafe"
HEADER_NAME = "Strict-Transport-Security"
ScopeKey = tuple[str, str | None, int | None]


@rule(
    rule_id=MISSING_RULE_ID,
    title="Strict-Transport-Security header missing on Apache TLS scope",
    severity="medium",
    description=(
        "A TLS-enabled Apache scope does not set Strict-Transport-Security "
        "for all response classes."
    ),
    recommendation=(
        "Set 'Header always set Strict-Transport-Security "
        "\"max-age=31536000; includeSubDomains\"' on TLS scopes."
    ),
    category="local",
    server_type="apache",
    order=358,
    tags=("headers", "tls"),
)
def find_missing_hsts_header(config_ast: ApacheConfigAst) -> list[Finding]:
    tls_scope_keys = _tls_scope_keys(config_ast)
    findings: list[Finding] = []
    for scope in iter_effective_header_scopes(config_ast, HEADER_NAME):
        if not _is_tls_header_scope(scope, tls_scope_keys):
            continue
        if not scope.missing_possible:
            continue
        findings.append(
            Finding(
                rule_id=MISSING_RULE_ID,
                title="Strict-Transport-Security header missing on Apache TLS scope",
                severity="medium",
                description=(
                    "TLS-enabled Apache scope does not set "
                    f"Strict-Transport-Security for all response classes. "
                    f"Scope: {scope.label}."
                ),
                recommendation=(
                    "Set Strict-Transport-Security with 'Header always set' "
                    "so redirects, errors, and successful responses all carry it."
                ),
                location=_scope_location(scope),
                metadata={"scope_name": scope.label},
            )
        )
    return findings


@rule(
    rule_id=UNSAFE_RULE_ID,
    title="Strict-Transport-Security header is weak",
    severity="medium",
    description="Apache sets Strict-Transport-Security to an invalid or weak value.",
    recommendation=(
        "Use a valid Strict-Transport-Security value with max-age of at least "
        "31536000 seconds."
    ),
    category="local",
    server_type="apache",
    order=359,
    tags=("headers", "tls"),
)
def find_hsts_header_unsafe(config_ast: ApacheConfigAst) -> list[Finding]:
    tls_scope_keys = _tls_scope_keys(config_ast)
    findings: list[Finding] = []
    for scope in iter_effective_header_scopes(config_ast, HEADER_NAME):
        if not _is_tls_header_scope(scope, tls_scope_keys):
            continue
        unsafe = _unsafe_hsts_setting(scope)
        if unsafe is None:
            continue
        setting, value, reason = unsafe
        findings.append(
            Finding(
                rule_id=UNSAFE_RULE_ID,
                title="Strict-Transport-Security header is weak",
                severity="medium",
                description=(
                    f"Apache scope {scope.label!r} sets "
                    f"Strict-Transport-Security to {value!r}: {reason}."
                ),
                recommendation=(
                    "Set Strict-Transport-Security to a valid policy such as "
                    "'max-age=31536000; includeSubDomains'."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=setting.source.file_path,
                    line=setting.source.line,
                ),
                metadata={"scope_name": scope.label},
            )
        )
    return findings


def _tls_scope_keys(config_ast: ApacheConfigAst) -> set[ScopeKey]:
    return {
        _scope_key(
            scope.label,
            (
                scope.context.node.source
                if scope.context is not None
                else scope.fallback_source
            ),
        )
        for scope in iter_tls_scopes(config_ast)
    }


def _is_tls_header_scope(
    scope: ApacheHeaderScope,
    tls_scope_keys: set[ScopeKey],
) -> bool:
    return scope.auditable and _scope_key(scope.label, scope.source) in tls_scope_keys


def _scope_key(label: str, source: ApacheSourceSpan | None) -> ScopeKey:
    return (
        label,
        source.file_path if source is not None else None,
        source.line if source is not None else None,
    )


def _unsafe_hsts_setting(
    scope: ApacheHeaderScope,
) -> tuple[ApacheHeaderSetting, str, str] | None:
    for outcome in scope.outcomes:
        settings = outcome.always
        if not settings:
            continue
        effective_value = _effective_static_value(settings)
        if effective_value is None:
            continue
        reason = hsts_policy_reason(effective_value)
        if reason is None:
            continue
        return _last_setting(settings), effective_value, reason
    return None


def _effective_static_value(settings: list[ApacheHeaderSetting]) -> str | None:
    if any(setting.dynamic for setting in settings):
        return None
    values = [setting.value for setting in settings if setting.value is not None]
    return ", ".join(values) if values else ""


def _last_setting(settings: list[ApacheHeaderSetting]) -> ApacheHeaderSetting:
    return max(settings, key=lambda setting: setting.apply_index)


def _scope_location(scope: ApacheHeaderScope) -> SourceLocation | None:
    if scope.source is None:
        return None
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=scope.source.file_path,
        line=scope.source.line,
    )


__all__ = ["find_hsts_header_unsafe", "find_missing_hsts_header"]
