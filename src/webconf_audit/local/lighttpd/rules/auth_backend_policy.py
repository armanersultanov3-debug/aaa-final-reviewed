from __future__ import annotations

from collections.abc import Callable

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdConditionalScope,
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.directive_value_utils import (
    directive_location,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    effective_directive_for_scope,
    normalize_value,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

_FILE_BACKEND_USERFILE = {
    "htpasswd": "auth.backend.htpasswd.userfile",
    "htdigest": "auth.backend.htdigest.userfile",
    "plain": "auth.backend.plain.userfile",
}


@rule(
    rule_id="lighttpd.auth_backend_missing",
    title="Authentication backend missing",
    severity="medium",
    description="auth.require is configured without an auth.backend directive.",
    recommendation="Set auth.backend to the intended authentication backend.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=444,
)
def find_auth_backend_missing(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _find_auth_policy(
        config_ast,
        find_auth_backend_missing,
        _backend_missing,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.auth_backend_userfile_missing",
    title="Authentication backend user file missing",
    severity="medium",
    description="A file-based auth.backend is configured without its matching userfile directive.",
    recommendation="Set the matching auth.backend.*.userfile directive for the selected file backend.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=445,
)
def find_auth_backend_userfile_missing(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _find_auth_policy(
        config_ast,
        find_auth_backend_userfile_missing,
        _file_backend_userfile_missing,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


def _find_auth_policy(
    config_ast: LighttpdConfigAst,
    rule_fn: Callable[..., list[Finding]],
    violates: Callable[[dict[str, LighttpdEffectiveDirective]], LighttpdEffectiveDirective | None],
    *,
    effective_config: LighttpdEffectiveConfig | None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None,
    request_context: LighttpdRequestContext | None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        directive = violates(merged_directives)
        return _finding(rule_fn, directive, config_ast)

    if effective_config is not None:
        findings = _finding(rule_fn, violates(effective_config.global_directives), config_ast)
        seen = {_finding_key(finding) for finding in findings}
        for scope in effective_config.conditional_scopes:
            scoped = _directives_for_scope(effective_config, scope)
            directive = violates(scoped)
            for finding in _finding(rule_fn, directive, config_ast):
                key = _finding_key(finding)
                if key in seen:
                    continue
                findings.append(finding)
                seen.add(key)
        return findings

    return []


def _directives_for_scope(
    effective_config: LighttpdEffectiveConfig,
    scope: LighttpdConditionalScope,
) -> dict[str, LighttpdEffectiveDirective]:
    names = {
        "auth.require",
        "auth.backend",
        *list(_FILE_BACKEND_USERFILE.values()),
    }
    directives: dict[str, LighttpdEffectiveDirective] = {}
    for name in names:
        directive = effective_directive_for_scope(effective_config, scope, name)
        if directive is not None:
            directives[name] = directive
    return directives


def _backend_missing(
    directives: dict[str, LighttpdEffectiveDirective],
) -> LighttpdEffectiveDirective | None:
    auth = directives.get("auth.require")
    if auth is None or "auth.backend" in directives:
        return None
    return auth


def _file_backend_userfile_missing(
    directives: dict[str, LighttpdEffectiveDirective],
) -> LighttpdEffectiveDirective | None:
    auth = directives.get("auth.require")
    backend = directives.get("auth.backend")
    if auth is None or backend is None:
        return None
    userfile_name = _FILE_BACKEND_USERFILE.get(normalize_value(backend.value))
    if userfile_name is None or userfile_name in directives:
        return None
    return backend


def _finding(
    rule_fn: Callable[..., list[Finding]],
    directive: LighttpdEffectiveDirective | None,
    config_ast: LighttpdConfigAst,
) -> list[Finding]:
    if directive is None:
        return []
    return [
        finding_from_rule(
            rule_fn,
            location=directive_location(directive, fallback=default_location(config_ast)),
        )
    ]


def _finding_key(finding: Finding) -> tuple[str, str | None, int | None]:
    location = finding.location
    return (
        finding.rule_id,
        location.file_path if location is not None else None,
        location.line if location is not None else None,
    )


__all__ = [
    "find_auth_backend_missing",
    "find_auth_backend_userfile_missing",
]
