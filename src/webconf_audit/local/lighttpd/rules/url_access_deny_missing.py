from __future__ import annotations

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
    order=413,
)
def find_url_access_deny_missing(config_ast: LighttpdConfigAst) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    assignments: list[LighttpdAssignmentNode] = []
    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name == "url.access-deny":
            assignments.append(node)

    missing_markers = _missing_markers(assignments)
    if not missing_markers:
        return []

    description = (
        "url.access-deny is not configured to block dangerous file extensions "
        "and generated artifacts."
    )
    if assignments:
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


def _missing_markers(assignments: list[LighttpdAssignmentNode]) -> list[str]:
    if not assignments:
        return list(LIGHTTPD_URL_ACCESS_DENY_MARKERS)

    combined = " ".join(assignment.value for assignment in assignments).lower()
    return [
        marker
        for marker in LIGHTTPD_URL_ACCESS_DENY_MARKERS
        if marker.lower() not in combined
    ]


__all__ = ["find_url_access_deny_missing"]
