"""Nginx CVE-related DAV COPY/MOVE alias-prefix-location rule."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule

RULE_ID = "nginx.dav_move_copy_alias_prefix_location"
TITLE = "Nginx DAV COPY or MOVE is enabled in an alias prefix location"
DESCRIPTION = (
    "An Nginx prefix location combines alias with dav_methods COPY or MOVE. "
    "This CVE-2026-27654-related pattern depends on Nginx version and module "
    "build state, but it is a risky WebDAV file-operation topology."
)
RECOMMENDATION = (
    "Avoid enabling WebDAV COPY or MOVE inside alias-backed prefix locations, "
    "prefer a non-alias mapping or restrict DAV methods, and confirm the Nginx "
    "version is patched for CVE-2026-27654."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("cve", "webdav", "alias"),
    standards=(
        StandardReference(
            standard="CVE",
            reference="CVE-2026-27654",
            url="https://nginx.org/en/security_advisories.html",
            coverage="related",
            note=(
                "Detects the directive topology; affected-version and module "
                "build state are not proven by static config analysis."
            ),
        ),
    ),
    order=285,
)
def find_dav_move_copy_alias_prefix_location(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "location":
            continue
        if not _is_prefix_location(node):
            continue
        if not find_child_directives(node, "alias"):
            continue
        for dav_methods in find_child_directives(node, "dav_methods"):
            enabled_methods = {arg.lower() for arg in dav_methods.args}
            if not {"copy", "move"} & enabled_methods:
                continue
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=TITLE,
                    severity="medium",
                    description=DESCRIPTION,
                    recommendation=RECOMMENDATION,
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=dav_methods.source.file_path,
                        line=dav_methods.source.line,
                    ),
                )
            )
    return findings


def _is_prefix_location(location: BlockNode) -> bool:
    if not location.args:
        return False
    first = location.args[0]
    if first in {"~", "~*", "="}:
        return False
    if first == "^~":
        return len(location.args) > 1
    return first.startswith("/")


__all__ = ["find_dav_move_copy_alias_prefix_location"]
