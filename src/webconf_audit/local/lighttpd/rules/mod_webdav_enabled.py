"""lighttpd.mod_webdav_enabled -- WebDAV module loaded."""

from __future__ import annotations

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    collect_modules,
    default_location,
    iter_all_nodes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.mod_webdav_enabled"


@rule(
    rule_id=RULE_ID,
    title="WebDAV module loaded",
    severity="low",
    description="mod_webdav is loaded in server.modules.",
    recommendation="Disable mod_webdav unless WebDAV publishing is intentionally required.",
    category="local",
    server_type="lighttpd",
    order=431,
)
def find_mod_webdav_enabled(config_ast: LighttpdConfigAst) -> list[Finding]:
    if "mod_webdav" not in collect_modules(config_ast):
        return []

    assignment = _assignment_loading_mod_webdav(config_ast)
    location = (
        SourceLocation(
            mode="local",
            kind="file",
            file_path=assignment.source.file_path,
            line=assignment.source.line,
        )
        if assignment is not None
        else default_location(config_ast)
    )
    return [finding_from_rule(find_mod_webdav_enabled, location=location)]


def _assignment_loading_mod_webdav(
    config_ast: LighttpdConfigAst,
) -> LighttpdAssignmentNode | None:
    last_modules_assignment: LighttpdAssignmentNode | None = None
    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != "server.modules":
            continue
        last_modules_assignment = node
        if "mod_webdav" in node.value:
            return node
    return last_modules_assignment


__all__ = ["find_mod_webdav_enabled"]
