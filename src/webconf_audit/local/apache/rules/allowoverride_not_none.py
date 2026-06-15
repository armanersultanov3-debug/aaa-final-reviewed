"""apache.allowoverride_not_none -- Directory scope allows .htaccess overrides."""

from __future__ import annotations

from webconf_audit.local.apache.root_directory import (
    group_directory_blocks_by_path,
    is_os_root_directory_group,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._block_policy_utils import default_location, iter_blocks
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule
from webconf_audit.standards import cwe, owasp_top10_2021

RULE_ID = "apache.allowoverride_not_none"


@rule(
    rule_id=RULE_ID,
    title="Directory scope allows .htaccess overrides",
    severity="medium",
    description=(
        "A Directory scope does not enforce 'AllowOverride None', leaving "
        ".htaccess override behavior enabled or ambiguous for CIS hardening."
    ),
    recommendation=(
        "Set 'AllowOverride None' in the OS-root Directory scope and avoid "
        "enabling .htaccess overrides in application Directory scopes."
    ),
    category="local",
    server_type="apache",
    standards=(
        cwe(732),
        owasp_top10_2021("A05:2021"),
        StandardReference(
            standard="CIS",
            reference="Apache HTTP Server 2.4 v2.3.0 §4.3/§4.4",
            url="https://www.cisecurity.org/benchmark/apache_http_server",
            coverage="partial",
            note=(
                "Validates the OS-root AllowOverride None baseline and explicit "
                "non-None Directory scopes; explicit non-root declarations are "
                "paired with apache.directory_without_allowoverride."
            ),
        ),
    ),
    order=341,
)
def find_allowoverride_not_none(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    directory_blocks = list(iter_blocks(config_ast.nodes, frozenset({"directory"})))
    groups = group_directory_blocks_by_path(directory_blocks)

    if not any(is_os_root_directory_group(blocks) for blocks in groups.values()):
        findings.append(_make_missing_root_finding(config_ast))

    for blocks in groups.values():
        directive = _effective_allowoverride_directive(blocks)
        if directive is not None and _is_allowoverride_none(directive):
            continue

        if directive is None and not is_os_root_directory_group(blocks):
            continue

        findings.append(_make_finding(blocks[-1], directive=directive))

    return findings


def _make_missing_root_finding(config_ast: ApacheConfigAst) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Directory scope allows .htaccess overrides",
        severity="medium",
        description=(
            "Apache config does not define an OS-root '<Directory />' scope "
            "with 'AllowOverride None'. CIS Apache hardening expects this "
            "baseline before more specific Directory scopes."
        ),
        recommendation=(
            "Add '<Directory />' with 'AllowOverride None' near the global "
            "Directory baseline."
        ),
        location=default_location(config_ast),
    )


def _make_finding(
    block: ApacheBlockNode,
    *,
    directive: ApacheDirectiveNode | None,
) -> Finding:
    if directive is None:
        detail = "does not set 'AllowOverride None'"
    else:
        configured = " ".join(directive.args) if directive.args else "<missing value>"
        detail = f"sets 'AllowOverride {configured}'"

    return Finding(
        rule_id=RULE_ID,
        title="Directory scope allows .htaccess overrides",
        severity="medium",
        description=(
            f"This Directory scope {detail}; CIS Apache hardening expects "
            "'AllowOverride None' for centrally managed configuration."
        ),
        recommendation=(
            "Set this Directory scope to 'AllowOverride None' and move "
            "required overrides into the main Apache configuration."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=(directive.source if directive is not None else block.source).file_path,
            line=(directive.source if directive is not None else block.source).line,
        ),
    )

def _is_allowoverride_none(directive: ApacheDirectiveNode) -> bool:
    return len(directive.args) == 1 and directive.args[0].lower() == "none"


def _find_allowoverride_directive(block: ApacheBlockNode) -> ApacheDirectiveNode | None:
    winner: ApacheDirectiveNode | None = None
    for child in block.children:
        if (
            isinstance(child, ApacheDirectiveNode)
            and child.name.lower() == "allowoverride"
        ):
            winner = child
    return winner


def _effective_allowoverride_directive(
    blocks: list[ApacheBlockNode],
) -> ApacheDirectiveNode | None:
    effective: ApacheDirectiveNode | None = None
    for block in blocks:
        directive = _find_allowoverride_directive(block)
        if directive is not None:
            effective = directive
    return effective


__all__ = ["find_allowoverride_not_none"]
