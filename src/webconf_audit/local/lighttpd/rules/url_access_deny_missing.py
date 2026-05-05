from __future__ import annotations

from collections.abc import Iterable

from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdConditionalScope,
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    iter_all_nodes,
)
from webconf_audit.local.lighttpd.rules.redirect_scope_utils import (
    is_redirect_only_config,
)
from webconf_audit.local.sensitive_artifact_policy import (
    LIGHTTPD_URL_ACCESS_DENY_MARKERS,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.url_access_deny_missing"
URL_ACCESS_DENY_NAME = "url.access-deny"


@rule(
    rule_id=RULE_ID,
    title="No file extension access restrictions",
    severity="medium",
    description=(
        "url.access-deny is not configured to block dangerous file extensions "
        "and generated artifacts such as .inc, .bak, .sql, .conf, .env, "
        ".DS_Store, Thumbs.db, composer manifests, and package-lock.json."
    ),
    recommendation=(
        'Set url.access-deny to include ".inc", ".bak", ".sql", ".log", '
        '".conf", ".env", generated artifact files, and editor metadata '
        "to prevent access to sensitive file types."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=413,
)
def find_url_access_deny_missing(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    missing_markers = _missing_markers(
        config_ast,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )
    if not missing_markers:
        return []

    description = (
        "url.access-deny is not configured to block dangerous file extensions "
        "and generated artifacts."
    )
    if missing_markers != list(LIGHTTPD_URL_ACCESS_DENY_MARKERS):
        description += " Missing markers: " + ", ".join(missing_markers)
    return [
        Finding(
            rule_id=RULE_ID,
            title="No file extension access restrictions",
            severity="medium",
            description=description,
            recommendation=(
                'Set url.access-deny to include ".inc", ".bak", ".sql", ".log", '
                '".conf", ".env", generated artifact files, and editor metadata '
                "to prevent access to sensitive file types."
            ),
            location=default_location(config_ast),
        )
    ]


def _missing_markers(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None,
    request_context: LighttpdRequestContext | None,
) -> list[str]:
    if request_context is not None and merged_directives is not None:
        directive = merged_directives.get(URL_ACCESS_DENY_NAME)
        return _missing_markers_from_text(directive.value if directive else None)

    if effective_config is not None:
        return _missing_markers_from_effective_scopes(effective_config)

    return _missing_markers_from_text(_combined_assignment_text(config_ast))


def _missing_markers_from_effective_scopes(
    effective_config: LighttpdEffectiveConfig,
) -> list[str]:
    missing_by_scope = [
        _missing_markers_from_text(scope_text)
        for scope_text in _effective_url_access_deny_texts(effective_config)
    ]
    return _unique_markers(
        marker
        for missing_markers in missing_by_scope
        for marker in missing_markers
    )


def _effective_url_access_deny_texts(
    effective_config: LighttpdEffectiveConfig,
) -> list[str | None]:
    scopes: list[str | None] = [
        _directive_text(effective_config.global_directives.get(URL_ACCESS_DENY_NAME))
    ]
    scopes.extend(
        _effective_url_access_deny_for_scope(effective_config, scope_index)
        for scope_index, _scope in enumerate(effective_config.conditional_scopes)
    )
    return scopes


def _effective_url_access_deny_for_scope(
    effective_config: LighttpdEffectiveConfig,
    target_scope_index: int,
) -> str | None:
    target_scope = effective_config.conditional_scopes[target_scope_index]
    text = _directive_text(effective_config.global_directives.get(URL_ACCESS_DENY_NAME))

    for candidate_scope in effective_config.conditional_scopes[: target_scope_index + 1]:
        if not _scope_applies_to(candidate_scope, target_scope):
            continue

        directive = candidate_scope.directives.get(URL_ACCESS_DENY_NAME)
        if directive is None:
            continue

        text = _apply_effective_assignment(text, directive)

    return text


def _scope_applies_to(
    candidate_scope: LighttpdConditionalScope,
    target_scope: LighttpdConditionalScope,
) -> bool:
    candidate_path = candidate_scope.branch_path
    target_path = target_scope.branch_path
    return target_path[: len(candidate_path)] == candidate_path


def _apply_effective_assignment(
    current_text: str | None,
    directive: LighttpdEffectiveDirective,
) -> str:
    if directive.operator == "+=" and current_text:
        return current_text + " " + directive.value
    return directive.value


def _directive_text(directive: LighttpdEffectiveDirective | None) -> str | None:
    return directive.value if directive is not None else None


def _combined_assignment_text(config_ast: LighttpdConfigAst) -> str | None:
    assignments: list[LighttpdAssignmentNode] = []
    for node in iter_all_nodes(config_ast):
        if isinstance(node, LighttpdAssignmentNode) and node.name == URL_ACCESS_DENY_NAME:
            assignments.append(node)
    if not assignments:
        return None
    return " ".join(assignment.value for assignment in assignments)


def _missing_markers_from_text(text: str | None) -> list[str]:
    if not text:
        return list(LIGHTTPD_URL_ACCESS_DENY_MARKERS)

    combined = text.lower()
    return [
        marker
        for marker in LIGHTTPD_URL_ACCESS_DENY_MARKERS
        if marker.lower() not in combined
    ]


def _unique_markers(markers: Iterable[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for marker in markers:
        if marker in seen:
            continue
        unique.append(marker)
        seen.add(marker)
    return unique


__all__ = ["find_url_access_deny_missing"]
