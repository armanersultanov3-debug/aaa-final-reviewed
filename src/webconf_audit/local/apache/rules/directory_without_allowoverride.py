from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule
from webconf_audit.standards import owasp_top10_2021

RULE_ID = "apache.directory_without_allowoverride"


@rule(
    rule_id=RULE_ID,
    title="Directory block lacks explicit AllowOverride",
    severity="low",
    description=(
        "This non-root Directory block does not set AllowOverride explicitly. "
        "CIS Apache expects each Directory scope below the OS-root baseline to "
        "declare its own AllowOverride policy."
    ),
    recommendation=(
        "Set AllowOverride explicitly for each non-root Directory block, "
        "preferably 'AllowOverride None' or a narrow category list."
    ),
    category="local",
    server_type="apache",
    standards=(
        owasp_top10_2021("A05:2021"),
        StandardReference(
            standard="CIS",
            reference="Apache HTTP Server 2.4 v2.3.0 §4.4",
            url="https://www.cisecurity.org/benchmark/apache_http_server",
            note=(
                "Non-root Directory scopes should declare AllowOverride "
                "explicitly; value policy is paired with "
                "apache.allowoverride_not_none."
            ),
        ),
    ),
    order=303,
)
def find_directory_without_allowoverride(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    directory_blocks = _iter_directory_blocks(config_ast.nodes)

    for block in directory_blocks:
        if not block.args:
            continue
        if _is_os_root_directory(block):
            continue
        if _has_explicit_allowoverride(block):
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Directory block lacks explicit AllowOverride",
                severity="low",
                description=(
                    "This non-root Directory block does not set AllowOverride "
                    "explicitly. CIS Apache expects each Directory scope below "
                    "the OS-root baseline to declare its own AllowOverride "
                    "policy."
                ),
                recommendation=(
                    "Set AllowOverride explicitly for each non-root Directory "
                    "block, preferably 'AllowOverride None' or a narrow "
                    "category list."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=block.source.file_path,
                    line=block.source.line,
                ),
            )
        )

    return findings


def _has_explicit_allowoverride(block: ApacheBlockNode) -> bool:
    return any(
        isinstance(child, ApacheDirectiveNode) and child.name.lower() == "allowoverride"
        for child in block.children
    )


def _is_os_root_directory(block: ApacheBlockNode) -> bool:
    return bool(block.args) and block.args[0] == "/"


def _iter_directory_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheBlockNode]:
    blocks: list[ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            name = node.name.lower()
            if name == "directory":
                blocks.append(node)
                continue

            blocks.extend(_iter_directory_blocks(node.children))
    return blocks


__all__ = ["find_directory_without_allowoverride"]
