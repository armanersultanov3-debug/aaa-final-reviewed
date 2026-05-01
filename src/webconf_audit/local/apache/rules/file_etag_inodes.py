from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.file_etag_inodes"
_RISKY_TOKENS = frozenset({"all", "inode", "+inode"})


@rule(
    rule_id=RULE_ID,
    title="FileETag includes inode data",
    severity="low",
    description="Apache FileETag configuration includes inode-derived values.",
    recommendation="Remove FileETag or set it to 'None' or 'MTime Size'.",
    category="local",
    server_type="apache",
    tags=("disclosure",),
    order=327,
)
def find_file_etag_inodes(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive in _iter_directives(config_ast.nodes, "fileetag"):
        risky_tokens = sorted(
            token for token in _normalized_args(directive.args) if token in _RISKY_TOKENS
        )
        if not risky_tokens:
            continue

        configured = " ".join(directive.args) if directive.args else "<missing value>"
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="FileETag includes inode data",
                severity="low",
                description=(
                    "Apache sets 'FileETag "
                    f"{configured}', which includes inode-derived ETag data."
                ),
                recommendation="Remove FileETag or set it to 'FileETag None' or 'FileETag MTime Size'.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


def _iter_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    directive_name: str,
) -> list[ApacheDirectiveNode]:
    matches: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if node.name.lower() == directive_name:
                matches.append(node)
            continue
        matches.extend(_iter_directives(node.children, directive_name))
    return matches


def _normalized_args(args: list[str]) -> list[str]:
    return [arg.lower() for arg in args]


__all__ = ["find_file_etag_inodes"]
