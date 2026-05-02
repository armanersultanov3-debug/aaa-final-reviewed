from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_http_method_restrictions"
TITLE = "Missing HTTP method restrictions"
DESCRIPTION = (
    "Sensitive Apache Location block does not define an explicit HTTP method "
    "restriction."
)
RECOMMENDATION = (
    "Add a '<LimitExcept ...>' block with 'Require all denied' or an equivalent "
    "'Require method ...' policy for sensitive locations."
)
SENSITIVE_LOCATION_MARKERS = ("/admin", "/login", "/api", "/upload", "/uploads")
LOCATION_BLOCK_NAMES = frozenset({"location", "locationmatch"})
TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)
AUTHZ_WRAPPER_BLOCKS = frozenset({"requireall", "requireany", "requirenone"})
METHOD_POLICY_WRAPPER_BLOCKS = TRANSPARENT_WRAPPER_BLOCKS | AUTHZ_WRAPPER_BLOCKS
METHOD_RESTRICTION_BLOCKS = frozenset({"limit", "limitexcept"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=340,
)
def find_missing_http_method_restrictions(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    for location in _iter_location_blocks(config_ast.nodes):
        if not _is_sensitive_location(location):
            continue
        if _location_has_method_restriction(location):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=DESCRIPTION,
                recommendation=RECOMMENDATION,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=location.source.file_path,
                    line=location.source.line,
                ),
            )
        )
    return findings


def _iter_location_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheBlockNode]:
    blocks: list[ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            continue
        if node.name.lower() in LOCATION_BLOCK_NAMES:
            blocks.append(node)
        blocks.extend(_iter_location_blocks(node.children))
    return blocks


def _is_sensitive_location(location: ApacheBlockNode) -> bool:
    if not location.args:
        return False
    value = " ".join(location.args).lower()
    return any(marker in value for marker in SENSITIVE_LOCATION_MARKERS)


def _location_has_method_restriction(location: ApacheBlockNode) -> bool:
    for child in location.children:
        if isinstance(child, ApacheDirectiveNode):
            if _is_require_method(child):
                return True
            continue

        child_name = child.name.lower()
        if child_name in METHOD_RESTRICTION_BLOCKS and _block_denies_access(child):
            return True
        if child_name in METHOD_POLICY_WRAPPER_BLOCKS and _location_has_method_restriction(
            child
        ):
            return True
    return False


def _is_require_method(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "require"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "method"
    )


def _block_denies_access(block: ApacheBlockNode) -> bool:
    for child in block.children:
        if isinstance(child, ApacheDirectiveNode):
            if _is_require_all_denied(child) or _is_legacy_deny_all(child):
                return True
            continue
        if child.name.lower() in TRANSPARENT_WRAPPER_BLOCKS and _block_denies_access(child):
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


__all__ = ["find_missing_http_method_restrictions"]
