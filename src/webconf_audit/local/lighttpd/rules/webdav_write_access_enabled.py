from __future__ import annotations

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.directive_value_utils import (
    directive_location,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    effective_directive_for_scope,
    normalize_value,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.webdav_write_access_enabled"


@rule(
    rule_id=RULE_ID,
    title="WebDAV write access enabled",
    severity="low",
    description="webdav.activate is enabled without webdav.is-readonly enabled.",
    recommendation=(
        "Disable WebDAV write access or set webdav.is-readonly = \"enable\" "
        "unless write publishing is intentionally exposed."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=432,
)
def find_webdav_write_access_enabled(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        activate = merged_directives.get("webdav.activate")
        if _is_write_enabled(activate, merged_directives.get("webdav.is-readonly")):
            return [_make_finding(activate)]
        return []

    if effective_config is not None:
        return _find_from_effective(effective_config)

    return []


def _find_from_effective(
    effective_config: LighttpdEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []
    global_activate = effective_config.global_directives.get("webdav.activate")
    global_readonly = effective_config.global_directives.get("webdav.is-readonly")
    if _is_write_enabled(global_activate, global_readonly):
        findings.append(_make_finding(global_activate))

    seen = {_finding_key(finding) for finding in findings}
    for scope in effective_config.conditional_scopes:
        activate = effective_directive_for_scope(
            effective_config,
            scope,
            "webdav.activate",
        )
        readonly = effective_directive_for_scope(
            effective_config,
            scope,
            "webdav.is-readonly",
        )
        if not _is_write_enabled(activate, readonly):
            continue
        finding = _make_finding(activate)
        key = _finding_key(finding)
        if key in seen:
            continue
        findings.append(finding)
        seen.add(key)
    return findings


def _is_write_enabled(
    activate: LighttpdEffectiveDirective | None,
    readonly: LighttpdEffectiveDirective | None,
) -> bool:
    if activate is None:
        return False
    if normalize_value(activate.value) != "enable":
        return False
    return readonly is None or normalize_value(readonly.value) != "enable"


def _make_finding(activate: LighttpdEffectiveDirective) -> Finding:
    return finding_from_rule(
        find_webdav_write_access_enabled,
        location=directive_location(activate),
    )


def _finding_key(finding: Finding) -> tuple[str, str | None, int | None]:
    location = finding.location
    return (
        finding.rule_id,
        location.file_path if location is not None else None,
        location.line if location is not None else None,
    )


__all__ = ["find_webdav_write_access_enabled"]
