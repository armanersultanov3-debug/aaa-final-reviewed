from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.merge_slashes_off"


@rule(
    rule_id=RULE_ID,
    title="Merge slashes disabled",
    severity="low",
    description=(
        "Nginx disables URI slash compression with 'merge_slashes off;', which can "
        "make location and upstream path normalization depend on repeated slashes."
    ),
    recommendation=(
        "Keep the default 'merge_slashes on;' unless the application explicitly "
        "requires repeated slashes and has matching path-normalization controls."
    ),
    category="local",
    server_type="nginx",
    order=269,
)
def find_merge_slashes_off(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if (
            isinstance(node, DirectiveNode)
            and node.name == "merge_slashes"
            and len(node.args) == 1
            and node.args[0].lower() == "off"
        ):
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Merge slashes disabled",
                    severity="low",
                    description=(
                        "Nginx disables URI slash compression with 'merge_slashes off;'."
                    ),
                    recommendation=(
                        "Keep 'merge_slashes on;' unless repeated slashes are required "
                        "and protected by deployment-specific path normalization."
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=node.source.file_path,
                        line=node.source.line,
                    ),
                )
            )

    return findings


__all__ = ["find_merge_slashes_off"]
