from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._block_policy_utils import iter_directives
from webconf_audit.local.apache.rules._log_policy_utils import (
    defined_log_format_name,
    defined_log_format_text,
    referenced_log_format_name,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.log_format_missing_fields"

_REQUIRED_FIELD_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("client address", ("%h", "%a")),
    ("remote user", ("%u",)),
    ("timestamp", ("%t", "%{", "}t")),
    ("request line", ("%r",)),
    ("status", ("%>s", "%s")),
    ("response size", ("%b", "%O")),
    ("referer", ("%{referer}i",)),
    ("user-agent", ("%{user-agent}i", "%{user_agent}i")),
    ("request ID", ("%{x-request-id}i", "%{x-correlation-id}i", "%L")),
    ("forwarded chain", ("%{x-forwarded-for}i",)),
    ("request timing", ("%d",)),
)
_TLS_FIELD_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("TLS protocol/cipher", ("%{ssl_protocol}x", "%{ssl_cipher}x")),
)


@rule(
    rule_id=RULE_ID,
    title="LogFormat misses detailed audit fields",
    severity="low",
    description="Apache LogFormat is present but misses recommended audit fields.",
    recommendation=(
        "Include client address, remote user, timestamp, request, status, "
        "response size, referer, user-agent, request ID, forwarded chain, "
        "request timing, and TLS protocol/cipher fields where applicable in "
        "access logs."
    ),
    category="local",
    server_type="apache",
    order=348,
)
def find_log_format_missing_fields(config_ast: ApacheConfigAst) -> list[Finding]:
    used_formats = _used_custom_log_format_names(config_ast)
    findings: list[Finding] = []

    for directive in iter_directives(config_ast.nodes, "logformat"):
        format_name = defined_log_format_name(directive)
        if format_name is None or format_name not in used_formats:
            continue

        format_text = defined_log_format_text(directive).lower()
        missing_fields = _missing_fields(
            format_text,
            tls_enabled=used_formats[format_name],
        )
        if not missing_fields:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="LogFormat misses detailed audit fields",
                severity="low",
                description=(
                    "Apache LogFormat misses recommended audit fields: "
                    + ", ".join(missing_fields)
                ),
                recommendation="Add the missing fields to the LogFormat used by CustomLog.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


def _used_custom_log_format_names(config_ast: ApacheConfigAst) -> dict[str, bool]:
    used: dict[str, bool] = {}
    _collect_custom_log_usage(config_ast.nodes, used, inherited_tls=False)
    return used


def _collect_custom_log_usage(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    used: dict[str, bool],
    *,
    inherited_tls: bool,
) -> None:
    scope_tls = inherited_tls or _nodes_use_tls(nodes)
    child_inherited_tls = inherited_tls or _direct_nodes_use_tls(nodes)

    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if node.name.lower() == "customlog":
                format_name = referenced_log_format_name(node)
                if format_name is not None:
                    used[format_name] = used.get(format_name, False) or scope_tls
            continue

        _collect_custom_log_usage(
            node.children,
            used,
            inherited_tls=child_inherited_tls,
        )


def _missing_fields(format_text: str, *, tls_enabled: bool) -> list[str]:
    missing: list[str] = []
    field_groups = list(_REQUIRED_FIELD_GROUPS)
    if tls_enabled:
        field_groups.extend(_TLS_FIELD_GROUPS)

    for label, markers in field_groups:
        if label == "timestamp":
            if "%t" in format_text or ("%{" in format_text and "}t" in format_text):
                continue
            missing.append(label)
            continue

        if not any(marker in format_text for marker in markers):
            missing.append(label)
    return missing


def _nodes_use_tls(nodes: list[ApacheDirectiveNode | ApacheBlockNode]) -> bool:
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if _directive_uses_tls(node):
                return True
            continue
        if _nodes_use_tls(node.children):
            return True
    return False


def _direct_nodes_use_tls(nodes: list[ApacheDirectiveNode | ApacheBlockNode]) -> bool:
    return any(
        isinstance(node, ApacheDirectiveNode) and _directive_uses_tls(node)
        for node in nodes
    )


def _directive_uses_tls(directive: ApacheDirectiveNode) -> bool:
    name = directive.name.lower()
    if name == "sslengine":
        return bool(directive.args) and directive.args[0].lower() == "on"
    return name in {"sslprotocol", "sslciphersuite", "sslcertificatefile"}


__all__ = ["find_log_format_missing_fields"]
