from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    AstNode,
    BlockNode,
    ConfigAst,
    DirectiveNode,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.proxy_missing_source_ip_headers"

_REQUIRED_PROXY_HEADERS = {
    "x-forwarded-for": {"$proxy_add_x_forwarded_for", "$remote_addr"},
    "x-real-ip": {"$remote_addr"},
    "x-forwarded-proto": {"$scheme"},
}


@rule(
    rule_id=RULE_ID,
    title="Proxy block does not forward client source headers",
    severity="low",
    description="A proxy_pass block does not forward client source IP and protocol headers.",
    recommendation=(
        "Set X-Forwarded-For, X-Real-IP, and X-Forwarded-Proto with proxy_set_header "
        "in proxied contexts."
    ),
    category="local",
    server_type="nginx",
    order=259,
)
def find_proxy_missing_source_ip_headers(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    _walk_blocks(config_ast.nodes, {}, findings)
    return findings


def _walk_blocks(
    nodes: list[AstNode],
    inherited_headers: dict[str, str],
    findings: list[Finding],
) -> None:
    for node in nodes:
        if not isinstance(node, BlockNode):
            continue

        headers = inherited_headers | _proxy_headers(node)
        if _has_proxy_pass(node) and not _has_required_headers(headers):
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Proxy block does not forward client source headers",
                    severity="low",
                    description=(
                        "proxy_pass is used without forwarding X-Forwarded-For, "
                        "X-Real-IP, and X-Forwarded-Proto with expected values."
                    ),
                    recommendation=(
                        "Add proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; "
                        "proxy_set_header X-Real-IP $remote_addr; and "
                        "proxy_set_header X-Forwarded-Proto $scheme."
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=node.source.file_path,
                        line=node.source.line,
                    ),
                )
            )

        _walk_blocks(node.children, headers, findings)


def _proxy_headers(block: BlockNode) -> dict[str, str]:
    headers: dict[str, str] = {}
    for child in block.children:
        if not isinstance(child, DirectiveNode) or child.name != "proxy_set_header":
            continue
        if len(child.args) < 2:
            continue
        headers[child.args[0].lower()] = child.args[1]
    return headers


def _has_proxy_pass(block: BlockNode) -> bool:
    return any(
        isinstance(child, DirectiveNode) and child.name == "proxy_pass"
        for child in block.children
    )


def _has_required_headers(headers: dict[str, str]) -> bool:
    return all(
        headers.get(header_name) in allowed_values
        for header_name, allowed_values in _REQUIRED_PROXY_HEADERS.items()
    )


__all__ = ["find_proxy_missing_source_ip_headers"]
