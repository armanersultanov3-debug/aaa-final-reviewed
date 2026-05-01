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

    for directive in _effective_file_etag_directives(config_ast.nodes):
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


_TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)


def _effective_file_etag_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    scope_key: tuple[int, ...] = (),
) -> list[ApacheDirectiveNode]:
    effective: dict[tuple[int, ...], ApacheDirectiveNode] = {}
    _collect_effective_file_etag_directives(
        nodes,
        scope_key=scope_key,
        effective=effective,
    )
    return list(effective.values())


def _collect_effective_file_etag_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    scope_key: tuple[int, ...],
    effective: dict[tuple[int, ...], ApacheDirectiveNode],
) -> None:
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if node.name.lower() == "fileetag":
                effective[scope_key] = node
            continue

        child_scope = scope_key
        if node.name.lower() not in _TRANSPARENT_WRAPPER_BLOCKS:
            child_scope = (*scope_key, id(node))
        _collect_effective_file_etag_directives(
            node.children,
            scope_key=child_scope,
            effective=effective,
        )


def _normalized_args(args: list[str]) -> list[str]:
    return [arg.lower() for arg in args]


__all__ = ["find_file_etag_inodes"]
