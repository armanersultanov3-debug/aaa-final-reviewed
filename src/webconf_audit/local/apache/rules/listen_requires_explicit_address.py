"""Implements rule ``apache.listen_requires_explicit_address``.

Location: ``src/webconf_audit/local/apache/rules/listen_requires_explicit_address.py``.
"""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.listen_requires_explicit_address"
TITLE = "Listen directive does not use an explicit address"
DESCRIPTION = (
    "Apache Listen directives should bind only to explicit intended IP "
    "addresses rather than every interface."
)
RECOMMENDATION = (
    "Replace port-only or wildcard Listen values with explicit IP:port "
    "bindings such as 'Listen 192.0.2.10:80'."
)
TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=362,
)
def find_listen_requires_explicit_address(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    for directive in _iter_server_directives(config_ast.nodes):
        if directive.name.lower() != "listen":
            continue
        reason = _unsafe_listen_reason(directive.args)
        if reason is None:
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    f"Apache Listen value '{_configured_value(directive)}' "
                    f"{reason}."
                ),
                recommendation=RECOMMENDATION,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )
    return findings


def _iter_server_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
            continue
        if node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
            directives.extend(_iter_server_directives(node.children))
    return directives


def _unsafe_listen_reason(args: list[str]) -> str | None:
    if not args:
        return "does not specify an IP address"

    address = _listen_host(args[0])
    if address is None:
        return "specifies only a port and no IP address"

    normalized = address.strip().strip("[]").lower()
    if normalized in {"", "*", "_default_"}:
        return "uses a wildcard address"

    try:
        parsed = ip_address(normalized)
    except ValueError:
        return "does not use a literal IP address"

    if parsed.version == 6 and parsed.ipv4_mapped == IPv4Address("0.0.0.0"):
        return "uses an IPv4-mapped all-zero wildcard address"
    if parsed.is_unspecified:
        return "uses an all-zero wildcard address"
    return None


def _listen_host(value: str) -> str | None:
    value = value.strip()
    if not value or value.isdigit():
        return None

    if value.startswith("[") and "]" in value:
        host, _, _remainder = value[1:].partition("]")
        return host

    if ":" not in value:
        return value

    host, _, port = value.rpartition(":")
    if port.isdigit():
        return host
    return value


def _configured_value(directive: ApacheDirectiveNode) -> str:
    return " ".join(directive.args) if directive.args else "<missing>"


__all__ = ["find_listen_requires_explicit_address"]
