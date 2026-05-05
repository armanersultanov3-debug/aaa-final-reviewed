from __future__ import annotations

import re
from dataclasses import dataclass

from webconf_audit.local.nginx.parser.ast import (
    AstNode,
    BlockNode,
    ConfigAst,
    DirectiveNode,
    iter_nodes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.log_format_missing_fields"
_NGINX_VARIABLE_RE = re.compile(r"\$(?:\{(?P<braced>[A-Za-z0-9_]+)\}|(?P<plain>[A-Za-z0-9_]+))")
_ACCESS_LOG_OPTION_PREFIXES = ("buffer=", "flush=", "gzip=", "if=")
_UPSTREAM_DIRECTIVES = frozenset(
    {
        "proxy_pass",
        "fastcgi_pass",
        "uwsgi_pass",
        "scgi_pass",
        "grpc_pass",
        "memcached_pass",
    }
)

_BASE_FIELD_GROUPS = (
    ("timestamp", ("$time_iso8601", "$time_local")),
    ("client address", ("$remote_addr", "$realip_remote_addr")),
    ("remote user", ("$remote_user",)),
    ("request line", ("$request",)),
    ("status", ("$status",)),
    ("user-agent", ("$http_user_agent",)),
)

_REQUEST_CONTEXT_FIELD_GROUPS = (
    ("request ID", ("$request_id", "$http_x_request_id", "$trace_id")),
    ("forwarded chain", ("$http_x_forwarded_for", "$proxy_add_x_forwarded_for")),
)

_UPSTREAM_FIELD_GROUPS = (
    (
        "upstream timing",
        (
            "$upstream_response_time",
            "$upstream_connect_time",
            "$upstream_header_time",
        ),
    ),
)

_TLS_FIELD_GROUPS = (
    ("TLS protocol/cipher", ("$ssl_protocol", "$ssl_cipher")),
)


@dataclass(slots=True)
class _FormatUsage:
    needs_request_context: bool = False
    needs_upstream_timing: bool = False
    needs_tls_fields: bool = False

    def merge(self, other: "_FormatUsage") -> None:
        self.needs_request_context |= other.needs_request_context
        self.needs_upstream_timing |= other.needs_upstream_timing
        self.needs_tls_fields |= other.needs_tls_fields


@rule(
    rule_id=RULE_ID,
    title="log_format misses detailed audit fields",
    severity="low",
    description="log_format is present but does not include the recommended audit fields.",
    recommendation=(
        "Include timestamp, client address, remote user, request, status, "
        "user-agent, request ID, forwarded chain, upstream timing, and TLS "
        "protocol/cipher fields where those contexts apply."
    ),
    category="local",
    server_type="nginx",
    order=257,
)
def find_log_format_missing_fields(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    used_format_names = _used_log_format_names(config_ast)

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, DirectiveNode) or node.name != "log_format":
            continue
        if not node.args or node.args[0] not in used_format_names:
            continue
        format_text = " ".join(node.args[1:])
        parsed_vars = _extract_variables(format_text)
        missing_fields = _missing_fields(parsed_vars, used_format_names[node.args[0]])
        if not missing_fields:
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="log_format misses detailed audit fields",
                severity="low",
                description=(
                    "log_format does not include required audit fields: "
                    + ", ".join(missing_fields)
                ),
                recommendation=(
                    "Add the missing fields to the log_format used by access_log."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
            )
        )

    return findings


def _used_log_format_names(config_ast: ConfigAst) -> dict[str, _FormatUsage]:
    used_format_names: dict[str, _FormatUsage] = {}
    _collect_used_log_format_names(
        config_ast.nodes,
        used_format_names,
        inherited_usage=_FormatUsage(),
    )
    return used_format_names


def _collect_used_log_format_names(
    nodes: list[AstNode],
    used_format_names: dict[str, _FormatUsage],
    *,
    inherited_usage: _FormatUsage,
) -> None:
    scope_usage = _combine_usage(inherited_usage, _recursive_usage(nodes))
    child_inherited_usage = _combine_usage(inherited_usage, _direct_usage(nodes))

    for node in nodes:
        if isinstance(node, DirectiveNode):
            if node.name == "access_log":
                _record_access_log_format(node, used_format_names, scope_usage)
            continue

        _collect_used_log_format_names(
            node.children,
            used_format_names,
            inherited_usage=child_inherited_usage,
        )


def _record_access_log_format(
    node: DirectiveNode,
    used_format_names: dict[str, _FormatUsage],
    usage: _FormatUsage,
) -> None:
    if not node.args or node.args[0].lower() == "off":
        return
    if len(node.args) < 2:
        _merge_format_usage(used_format_names, "combined", usage)
        return
    format_name = node.args[1]
    if _is_access_log_option(format_name):
        _merge_format_usage(used_format_names, "combined", usage)
        return
    _merge_format_usage(used_format_names, format_name, usage)


def _merge_format_usage(
    used_format_names: dict[str, _FormatUsage],
    format_name: str,
    usage: _FormatUsage,
) -> None:
    if format_name not in used_format_names:
        used_format_names[format_name] = _FormatUsage()
    used_format_names[format_name].merge(usage)


def _combine_usage(left: _FormatUsage, right: _FormatUsage) -> _FormatUsage:
    return _FormatUsage(
        needs_request_context=left.needs_request_context
        or right.needs_request_context,
        needs_upstream_timing=left.needs_upstream_timing
        or right.needs_upstream_timing,
        needs_tls_fields=left.needs_tls_fields or right.needs_tls_fields,
    )


def _recursive_usage(nodes: list[AstNode]) -> _FormatUsage:
    has_upstream = _has_upstream_directive(nodes)
    return _FormatUsage(
        needs_request_context=_has_request_context(nodes) or has_upstream,
        needs_upstream_timing=has_upstream,
        needs_tls_fields=_has_tls_listener(nodes),
    )


def _direct_usage(nodes: list[AstNode]) -> _FormatUsage:
    has_upstream = any(
        isinstance(node, DirectiveNode) and node.name in _UPSTREAM_DIRECTIVES
        for node in nodes
    )
    return _FormatUsage(
        needs_request_context=any(
            isinstance(node, DirectiveNode)
            and node.name in {"proxy_set_header", "real_ip_header"}
            for node in nodes
        )
        or has_upstream,
        needs_upstream_timing=has_upstream,
        needs_tls_fields=any(
            isinstance(node, DirectiveNode)
            and (
                node.name in {"ssl_certificate", "ssl_certificate_key"}
                or node.name == "listen"
                and _listen_is_tls(node.args)
            )
            for node in nodes
        ),
    )


def _is_access_log_option(arg: str) -> bool:
    lowered = arg.lower()
    return lowered == "gzip" or any(
        lowered.startswith(prefix) for prefix in _ACCESS_LOG_OPTION_PREFIXES
    )


def _extract_variables(format_text: str) -> set[str]:
    return {
        f"${match.group('braced') or match.group('plain')}"
        for match in _NGINX_VARIABLE_RE.finditer(format_text)
    }


def _missing_fields(parsed_vars: set[str], usage: _FormatUsage) -> list[str]:
    field_groups = list(_BASE_FIELD_GROUPS)
    if usage.needs_request_context:
        field_groups.extend(_REQUEST_CONTEXT_FIELD_GROUPS)
    if usage.needs_upstream_timing:
        field_groups.extend(_UPSTREAM_FIELD_GROUPS)
    if usage.needs_tls_fields:
        field_groups.extend(_TLS_FIELD_GROUPS)

    return [
        label
        for label, markers in field_groups
        if not any(marker in parsed_vars for marker in markers)
    ]


def _has_request_context(nodes: list[AstNode]) -> bool:
    return any(
        isinstance(node, DirectiveNode)
        and node.name in {"proxy_set_header", "real_ip_header"}
        or isinstance(node, BlockNode)
        and _has_request_context(node.children)
        for node in nodes
    )


def _has_upstream_directive(nodes: list[AstNode]) -> bool:
    return any(
        isinstance(node, DirectiveNode)
        and node.name in _UPSTREAM_DIRECTIVES
        or isinstance(node, BlockNode)
        and _has_upstream_directive(node.children)
        for node in nodes
    )


def _has_tls_listener(nodes: list[AstNode]) -> bool:
    return any(
        (
            isinstance(node, DirectiveNode)
            and (
                node.name in {"ssl_certificate", "ssl_certificate_key"}
                or node.name == "listen"
                and _listen_is_tls(node.args)
            )
        )
        or (
            isinstance(node, BlockNode)
            and (
                _server_has_tls_listener(node)
                if node.name == "server"
                else _has_tls_listener(node.children)
            )
        )
        for node in nodes
    )


def _server_has_tls_listener(server: BlockNode) -> bool:
    for child in server.children:
        if not isinstance(child, DirectiveNode):
            continue
        if child.name == "listen" and _listen_is_tls(child.args):
            return True
        if child.name in {"ssl_certificate", "ssl_certificate_key"}:
            return True
    return False


def _listen_is_tls(args: list[str]) -> bool:
    lowered = {arg.lower() for arg in args}
    return "ssl" in lowered


__all__ = ["find_log_format_missing_fields"]
