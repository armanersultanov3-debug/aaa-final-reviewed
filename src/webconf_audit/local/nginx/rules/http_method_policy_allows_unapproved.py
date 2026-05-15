"""Implements rule ``nginx.http_method_policy_allows_unapproved``.

Location: ``src/webconf_audit/local/nginx/rules/http_method_policy_allows_unapproved.py``.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.http_method_policy_allows_unapproved"
TITLE = "HTTP method policy allows unapproved methods"
DESCRIPTION = (
    "Nginx defines a limit_except method allowlist that still permits methods "
    "outside the approved baseline."
)
RECOMMENDATION = (
    "Allow only required methods such as GET, HEAD, POST, and OPTIONS; restrict "
    "other methods with limit_except or an equivalent request-method policy."
)
APPROVED_METHODS = frozenset({"GET", "HEAD", "POST", "OPTIONS"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    order=220,
)
def find_http_method_policy_allows_unapproved(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "limit_except":
            continue

        unapproved_methods = _unapproved_methods(node.args)
        if not unapproved_methods:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    "Nginx method policy allows unapproved HTTP method(s): "
                    f"{', '.join(sorted(unapproved_methods))}."
                ),
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


def _unapproved_methods(methods: list[str]) -> set[str]:
    unapproved: set[str] = set()
    for method in methods:
        normalized = _normalize_method(method)
        if normalized and normalized not in APPROVED_METHODS:
            unapproved.add(normalized)
    return unapproved


def _normalize_method(method: str) -> str:
    stripped = method.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        stripped = stripped[1:-1]
    return stripped.upper()


__all__ = ["find_http_method_policy_allows_unapproved"]
