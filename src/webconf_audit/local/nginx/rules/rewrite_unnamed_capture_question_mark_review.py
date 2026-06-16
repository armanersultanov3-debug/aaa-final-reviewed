"""Nginx CVE-related rewrite unnamed-capture review rule."""

from __future__ import annotations

import re

from webconf_audit.local.nginx.parser.ast import (
    AstNode,
    BlockNode,
    ConfigAst,
    DirectiveNode,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule

RULE_ID = "nginx.rewrite_unnamed_capture_question_mark_review"
TITLE = "Nginx rewrite uses an unnamed capture and a question-mark replacement"
DESCRIPTION = (
    "An Nginx rewrite directive uses an unnamed regular-expression capture, "
    "references a numeric capture in a replacement containing '?', and is "
    "followed by rewrite, if, or set in the same block. This CVE-2026-42945-"
    "related shape is version-dependent and needs operator review."
)
RECOMMENDATION = (
    "Review the rewrite sequence, prefer named captures where possible, avoid "
    "ambiguous replacement query-string construction, and confirm the Nginx "
    "version is patched for CVE-2026-42945."
)

_UNNAMED_CAPTURE_PATTERN = re.compile(r"(?<!\\)\((?!\?)")
_NUMERIC_CAPTURE_REFERENCE_PATTERN = re.compile(r"\$[1-9][0-9]*")
_FOLLOWING_DIRECTIVE_NAMES = frozenset({"rewrite", "set"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="info",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("policy-review", "cve", "rewrite", "semantics"),
    standards=(
        StandardReference(
            standard="CVE",
            reference="CVE-2026-42945",
            url="https://nginx.org/en/security_advisories.html",
            coverage="related",
            note=(
                "Heuristic review of rewrite directive shape; affected-version "
                "state and exact runtime rewrite semantics are not proven."
            ),
        ),
    ),
    order=286,
)
def find_rewrite_unnamed_capture_question_mark_review(
    config_ast: ConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_find_in_sibling_nodes(config_ast.nodes))
    return findings


def _find_in_sibling_nodes(nodes: list[AstNode]) -> list[Finding]:
    findings: list[Finding] = []
    for index, node in enumerate(nodes):
        if isinstance(node, BlockNode):
            findings.extend(_find_in_sibling_nodes(node.children))
        if not isinstance(node, DirectiveNode) or node.name != "rewrite":
            continue
        if not _rewrite_has_review_shape(node):
            continue
        next_node = nodes[index + 1] if index + 1 < len(nodes) else None
        if not _is_following_rewrite_flow_node(next_node):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="info",
                description=DESCRIPTION,
                recommendation=RECOMMENDATION,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
            )
        )
    return findings


def _rewrite_has_review_shape(directive: DirectiveNode) -> bool:
    if len(directive.args) < 2:
        return False
    pattern, replacement = directive.args[0], directive.args[1]
    return (
        _UNNAMED_CAPTURE_PATTERN.search(pattern) is not None
        and "?" in replacement
        and _NUMERIC_CAPTURE_REFERENCE_PATTERN.search(replacement) is not None
    )


def _is_following_rewrite_flow_node(node: AstNode | None) -> bool:
    if isinstance(node, DirectiveNode):
        return node.name in _FOLLOWING_DIRECTIVE_NAMES
    return isinstance(node, BlockNode) and node.name == "if"


__all__ = ["find_rewrite_unnamed_capture_question_mark_review"]
