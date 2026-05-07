from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    block_has_unapproved_allowed_methods,
    explicit_module_inventory,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.http_method_policy_allows_unapproved"
TITLE = "HTTP method policy allows unapproved methods"
DESCRIPTION = (
    "Apache defines an HTTP method allowlist that still permits methods outside "
    "the approved baseline."
)
RECOMMENDATION = (
    "Allow only required methods such as GET, HEAD, POST, and OPTIONS; deny "
    "other methods with LimitExcept or an equivalent Require method policy."
)
APPROVED_METHODS = frozenset({"GET", "HEAD", "POST", "OPTIONS"})
TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)
REQUIRE_METHOD_WRAPPER_BLOCKS = TRANSPARENT_WRAPPER_BLOCKS | frozenset(
    {"requireall"}
)
REQUIRE_METHOD_SUPPRESSED_BLOCKS = frozenset({"requireany", "requirenone"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=341,
)
def find_http_method_policy_unsafe(config_ast: ApacheConfigAst) -> list[Finding]:
    modules = explicit_module_inventory(config_ast)
    return _policy_findings(config_ast.nodes, modules=modules)


def _policy_findings(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    modules: frozenset[str],
    require_method_active: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    for node in nodes:
        finding = _unsafe_method_policy_finding(
            node,
            modules=modules,
            require_method_active=require_method_active,
        )
        if finding is not None:
            findings.append(finding)

        if isinstance(node, ApacheBlockNode):
            findings.extend(
                _policy_findings(
                    node.children,
                    modules=modules,
                    require_method_active=_child_require_method_active(
                        node,
                        require_method_active,
                    ),
                )
            )
    return findings


def _unsafe_method_policy_finding(
    node: ApacheDirectiveNode | ApacheBlockNode,
    *,
    modules: frozenset[str],
    require_method_active: bool,
) -> Finding | None:
    source = node.source

    if isinstance(node, ApacheDirectiveNode) or not require_method_active:
        return None

    unapproved_methods = block_has_unapproved_allowed_methods(
        node,
        modules,
        APPROVED_METHODS,
    )
    if not unapproved_methods:
        return None

    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="low",
        description=(
            "Apache method policy allows unapproved HTTP method(s): "
            f"{', '.join(sorted(unapproved_methods))}."
        ),
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        ),
    )


def _child_require_method_active(
    block: ApacheBlockNode,
    parent_active: bool,
) -> bool:
    name = block.name.lower()
    if name in REQUIRE_METHOD_SUPPRESSED_BLOCKS:
        return False
    if name in REQUIRE_METHOD_WRAPPER_BLOCKS:
        return parent_active
    return parent_active


__all__ = ["find_http_method_policy_unsafe"]
