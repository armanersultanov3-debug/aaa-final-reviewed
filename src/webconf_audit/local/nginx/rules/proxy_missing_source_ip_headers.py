"""Implements rule ``nginx.proxy_missing_source_ip_headers``.

Location: ``src/webconf_audit/local/nginx/rules/proxy_missing_source_ip_headers.py``.
"""

from __future__ import annotations

from typing import NamedTuple

from webconf_audit.local.nginx.parser.ast import (
    AstNode,
    BlockNode,
    ConfigAst,
    DirectiveNode,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cis_nginx_v3_0_0

RULE_ID = "nginx.proxy_missing_source_ip_headers"
TITLE = "Upstream block does not forward client source headers"
DESCRIPTION = (
    "Upstream proxy_pass / fastcgi_pass / grpc_pass / uwsgi_pass scope does "
    "not forward client source-IP via its protocol's appropriate header."
)

_FORWARDED_FOR_VALUES = {"$proxy_add_x_forwarded_for", "$remote_addr"}
_REQUIRED_PROXY_HEADERS = {
    "x-forwarded-for": _FORWARDED_FOR_VALUES,
    "x-real-ip": {"$remote_addr"},
    "x-forwarded-proto": {"$scheme"},
}
_REQUIRED_FASTCGI_HEADERS = {
    "x-forwarded-for": _FORWARDED_FOR_VALUES,
    "x-real-ip": {"$remote_addr"},
}
_REQUIRED_GRPC_HEADERS = {
    "x-forwarded-for": _FORWARDED_FOR_VALUES,
}
_REQUIRED_UWSGI_HEADERS = {
    "x-forwarded-for": _FORWARDED_FOR_VALUES,
}


class _UpstreamProtocolSpec(NamedTuple):
    finding_protocol: str
    pass_directive: str
    header_directive: str
    required_headers: dict[str, set[str]]
    recommendation: str


_UPSTREAM_PROTOCOLS = (
    _UpstreamProtocolSpec(
        finding_protocol="http",
        pass_directive="proxy_pass",
        header_directive="proxy_set_header",
        required_headers=_REQUIRED_PROXY_HEADERS,
        recommendation=(
            "Add proxy_set_header X-Forwarded-For "
            "$proxy_add_x_forwarded_for; proxy_set_header X-Real-IP "
            "$remote_addr; and proxy_set_header X-Forwarded-Proto $scheme."
        ),
    ),
    _UpstreamProtocolSpec(
        finding_protocol="fastcgi",
        pass_directive="fastcgi_pass",
        header_directive="fastcgi_param",
        required_headers=_REQUIRED_FASTCGI_HEADERS,
        recommendation=(
            "Add fastcgi_param X-Forwarded-For "
            "$proxy_add_x_forwarded_for; and fastcgi_param X-Real-IP "
            "$remote_addr; in FastCGI contexts."
        ),
    ),
    _UpstreamProtocolSpec(
        finding_protocol="grpc",
        pass_directive="grpc_pass",
        header_directive="grpc_set_header",
        required_headers=_REQUIRED_GRPC_HEADERS,
        recommendation=(
            "Add grpc_set_header X-Forwarded-For "
            "$proxy_add_x_forwarded_for; in gRPC upstream contexts."
        ),
    ),
    _UpstreamProtocolSpec(
        finding_protocol="uwsgi",
        pass_directive="uwsgi_pass",
        header_directive="uwsgi_param",
        required_headers=_REQUIRED_UWSGI_HEADERS,
        recommendation=(
            "Add uwsgi_param X-Forwarded-For $proxy_add_x_forwarded_for; "
            "in uwsgi upstream contexts."
        ),
    ),
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=(
        "Set the protocol-appropriate source-IP forwarding directives in "
        "upstream contexts."
    ),
    category="local",
    server_type="nginx",
    standards=(
        cis_nginx_v3_0_0(
            "3.4",
            note=(
                "Covers source-IP forwarding for proxy_pass, fastcgi_pass, "
                "grpc_pass, and uwsgi_pass upstreams."
            ),
        ),
    ),
    order=259,
)
def find_proxy_missing_source_ip_headers(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    _walk_blocks(config_ast.nodes, {}, findings)
    return findings


def _walk_blocks(
    nodes: list[AstNode],
    inherited_headers_by_protocol: dict[str, dict[str, str]],
    findings: list[Finding],
) -> None:
    for node in nodes:
        if not isinstance(node, BlockNode):
            continue

        headers_by_protocol: dict[str, dict[str, str]] = {}
        for spec in _UPSTREAM_PROTOCOLS:
            headers, finding = _headers_and_finding_for_protocol(
                block=node,
                inherited_headers=inherited_headers_by_protocol.get(
                    spec.finding_protocol,
                    {},
                ),
                spec=spec,
            )
            headers_by_protocol[spec.finding_protocol] = headers
            if finding is not None:
                findings.append(finding)

        _walk_blocks(node.children, headers_by_protocol, findings)


def _headers_and_finding_for_protocol(
    *,
    block: BlockNode,
    inherited_headers: dict[str, str],
    spec: _UpstreamProtocolSpec,
) -> tuple[dict[str, str], Finding | None]:
    local_headers = _configured_headers(block, spec.header_directive)
    headers = local_headers if local_headers else dict(inherited_headers)
    if not _has_upstream_pass(block, spec.pass_directive):
        return headers, None
    if _has_required_headers(headers, spec.required_headers):
        return headers, None
    return headers, _finding_for_block(block, spec)


def _configured_headers(block: BlockNode, header_directive: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for child in block.children:
        if not isinstance(child, DirectiveNode) or child.name != header_directive:
            continue
        if len(child.args) < 2:
            continue
        headers[child.args[0].lower()] = child.args[1]
    return headers


def _finding_for_block(block: BlockNode, spec: _UpstreamProtocolSpec) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="low",
        description=DESCRIPTION,
        recommendation=spec.recommendation,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=block.source.file_path,
            line=block.source.line,
        ),
        metadata={"upstream_protocol": spec.finding_protocol},
    )


def _has_upstream_pass(block: BlockNode, pass_directive: str) -> bool:
    return any(
        isinstance(child, DirectiveNode) and child.name == pass_directive
        for child in block.children
    )


def _has_required_headers(
    headers: dict[str, str],
    required_headers: dict[str, set[str]],
) -> bool:
    for header_name, allowed_values in required_headers.items():
        header_value = headers.get(header_name)
        if header_value is None:
            return False
        normalized_allowed_values = {
            _normalize_header_value(value) for value in allowed_values
        }
        if _normalize_header_value(header_value) not in normalized_allowed_values:
            return False
    return True


def _normalize_header_value(value: str) -> str:
    return value.strip().strip('"').strip("'").lower()


__all__ = ["find_proxy_missing_source_ip_headers"]
