from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
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
DENY_WRAPPER_BLOCKS = REQUIRE_METHOD_WRAPPER_BLOCKS | frozenset(
    {"limit", "limitexcept"}
)


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
    return _policy_findings(config_ast.nodes)


def _policy_findings(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    require_method_active: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    for node in nodes:
        finding = _unsafe_method_policy_finding(
            node,
            require_method_active=require_method_active,
        )
        if finding is not None:
            findings.append(finding)

        if isinstance(node, ApacheBlockNode):
            findings.extend(
                _policy_findings(
                    node.children,
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
    require_method_active: bool,
) -> Finding | None:
    unapproved_methods: set[str]
    source = node.source

    if isinstance(node, ApacheDirectiveNode):
        if not require_method_active or not _is_require_method(node):
            return None
        unapproved_methods = _unapproved_methods(node.args[1:])
    elif (
        require_method_active
        and node.name.lower() == "limitexcept"
        and _block_denies_access(node)
    ):
        unapproved_methods = _unapproved_methods(node.args)
    else:
        return None

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


def _is_require_method(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "require"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "method"
    )


def _unapproved_methods(methods: list[str]) -> set[str]:
    return {
        method.upper()
        for method in methods
        if method.upper() not in APPROVED_METHODS
    }


def _block_denies_access(block: ApacheBlockNode) -> bool:
    for child in block.children:
        if isinstance(child, ApacheDirectiveNode):
            if _is_require_all_denied(child) or _is_legacy_deny_all(child):
                return True
            continue
        if child.name.lower() in DENY_WRAPPER_BLOCKS and _block_denies_access(
            child
        ):
            return True
    return False


def _is_require_all_denied(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "require"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "all"
        and directive.args[1].lower() in {"denied", "deny"}
    )


def _is_legacy_deny_all(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "deny"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "from"
        and directive.args[1].lower() == "all"
    )


__all__ = ["find_http_method_policy_unsafe"]
