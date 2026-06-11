"""nginx.http3_alt_svc_review -- opt-in HTTP/3 advertisement review."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
)
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cis_nginx_v3_0_0

RULE_ID = "nginx.http3_alt_svc_review"

_ADD_HEADER_INHERIT_MODES = frozenset({"on", "off", "merge"})
_MAX_REPORTED_VALUE_LEN = 240


@rule(
    rule_id=RULE_ID,
    title="HTTP/3 and Alt-Svc configuration needs operator review",
    severity="info",
    description=(
        "A QUIC listener is configured. Static analysis can report the "
        "effective HTTP/3 and Alt-Svc settings but cannot prove deployed "
        "QUIC reachability or client discovery."
    ),
    recommendation=(
        "Verify the HTTP/3 module, UDP reachability, effective http3 setting, "
        "and Alt-Svc protocol, port, and lifetime against deployment intent."
    ),
    category="local",
    server_type="nginx",
    tags=("policy-review", "http3", "headers", "tls"),
    standards=(
        cis_nginx_v3_0_0(
            "4.1.12",
            coverage="partial",
            note=(
                "Surfaces the QUIC listener, effective http3 state, and "
                "Alt-Svc advertisement for operator review; runtime HTTP/3 "
                "is not proven."
            ),
        ),
    ),
    order=284,
)
def find_http3_alt_svc_review(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header", "add_header_inherit", "http3"},
    ):
        quic_listeners = [
            directive
            for directive in find_child_directives(server_block, "listen")
            if any(arg.lower() == "quic" for arg in directive.args)
        ]
        if not quic_listeners:
            continue

        response_scopes = _response_scopes(
            server_block,
            inherited_headers=inherited_directives.get("add_header", []),
            inherited_mode=_last_inherit_mode(
                inherited_directives.get("add_header_inherit", []),
                default="on",
            ),
        )
        findings.append(
            _build_finding(
                listener=quic_listeners[0],
                http3_state=_effective_http3_state(
                    server_block,
                    inherited_directives,
                ),
                alt_svc_text=_format_alt_svc_state(response_scopes),
            )
        )

    return findings


def _effective_http3_state(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> str:
    directives = effective_child_directives(
        server_block,
        "http3",
        inherited_directives,
    )
    if not directives or not directives[-1].args:
        return "http3 on (default)"
    return f"http3 {' '.join(directives[-1].args)}"


def _response_scopes(
    server_block: BlockNode,
    *,
    inherited_headers: list[DirectiveNode],
    inherited_mode: str,
) -> list[tuple[str, list[DirectiveNode]]]:
    server_headers, server_mode = _effective_headers(
        server_block,
        inherited_headers=inherited_headers,
        inherited_mode=inherited_mode,
    )
    scopes = [("server", server_headers)]
    scopes.extend(
        _nested_response_scopes(
            server_block,
            inherited_headers=server_headers,
            inherited_mode=server_mode,
            parent_label="server",
            allowed_children={"location"},
        )
    )
    return scopes


def _nested_response_scopes(
    parent: BlockNode,
    *,
    inherited_headers: list[DirectiveNode],
    inherited_mode: str,
    parent_label: str,
    allowed_children: set[str],
) -> list[tuple[str, list[DirectiveNode]]]:
    scopes: list[tuple[str, list[DirectiveNode]]] = []
    for child in parent.children:
        if not isinstance(child, BlockNode) or child.name not in allowed_children:
            continue

        label = _scope_label(child, parent_label)
        headers, mode = _effective_headers(
            child,
            inherited_headers=inherited_headers,
            inherited_mode=inherited_mode,
        )
        scopes.append((label, headers))
        scopes.extend(
            _nested_response_scopes(
                child,
                inherited_headers=headers,
                inherited_mode=mode,
                parent_label=label,
                allowed_children={"if", "location"},
            )
        )
    return scopes


def _effective_headers(
    block: BlockNode,
    *,
    inherited_headers: list[DirectiveNode],
    inherited_mode: str,
) -> tuple[list[DirectiveNode], str]:
    mode = _last_inherit_mode(
        find_child_directives(block, "add_header_inherit"),
        default=inherited_mode,
    )
    local_headers = find_child_directives(block, "add_header")

    if mode == "off":
        return local_headers, mode
    if mode == "merge":
        return [*local_headers, *inherited_headers], mode
    if local_headers:
        return local_headers, mode
    return inherited_headers, mode


def _last_inherit_mode(
    directives: list[DirectiveNode],
    *,
    default: str,
) -> str:
    for directive in reversed(directives):
        if not directive.args:
            continue
        mode = directive.args[0].lower()
        if mode in _ADD_HEADER_INHERIT_MODES:
            return mode
    return default


def _scope_label(block: BlockNode, parent_label: str) -> str:
    current = " ".join((block.name, *block.args)).strip()
    if parent_label == "server":
        return current
    return f"{parent_label} > {current}"


def _format_alt_svc_state(
    response_scopes: list[tuple[str, list[DirectiveNode]]],
) -> str:
    observations: dict[
        tuple[str | None, int, str],
        tuple[DirectiveNode, list[str]],
    ] = {}
    missing_scopes: list[str] = []

    for scope_label, headers in response_scopes:
        alt_svc_headers = [
            (directive, value)
            for directive in headers
            if directive.args and directive.args[0].lower() == "alt-svc"
            if (value := _header_value(directive))
        ]
        if not alt_svc_headers:
            missing_scopes.append(scope_label)
            continue

        for directive, value in alt_svc_headers:
            key = (
                directive.source.file_path,
                directive.source.line,
                value,
            )
            if key not in observations:
                observations[key] = (directive, [])
            observations[key][1].append(scope_label)

    if not observations:
        return (
            "effective Alt-Svc header is missing from all reviewed "
            "server/location scopes"
        )

    rendered_observations = [
        _format_observation(directive, value=key[2], scopes=scopes)
        for key, (directive, scopes) in observations.items()
    ]
    text = "effective Alt-Svc observations: " + " | ".join(rendered_observations)
    if missing_scopes:
        text += "; scopes without effective Alt-Svc: " + ", ".join(missing_scopes)
    return text


def _header_value(directive: DirectiveNode) -> str:
    value_args = directive.args[1:]
    if len(value_args) > 1 and value_args[-1].lower() == "always":
        value_args = value_args[:-1]
    return _strip_matching_quotes(" ".join(value_args).strip())


def _format_observation(
    directive: DirectiveNode,
    *,
    value: str,
    scopes: list[str],
) -> str:
    displayed_value = (
        value[:_MAX_REPORTED_VALUE_LEN] + "..."
        if len(value) > _MAX_REPORTED_VALUE_LEN
        else value
    )
    source = directive.source.file_path or "<unknown file>"
    return (
        f"{displayed_value} at {source}, line {directive.source.line} "
        f"(effective in {', '.join(scopes)})"
    )


def _strip_matching_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


def _build_finding(
    *,
    listener: DirectiveNode,
    http3_state: str,
    alt_svc_text: str,
) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="HTTP/3 and Alt-Svc configuration needs operator review",
        severity="info",
        description=(
            f"QUIC listener found; effective {http3_state}; "
            f"{alt_svc_text}. Static analysis does not prove runtime HTTP/3."
        ),
        recommendation=(
            "Verify the HTTP/3 module, UDP reachability, effective http3 "
            "setting, and Alt-Svc protocol, port, and lifetime against "
            "deployment intent."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=listener.source.file_path,
            line=listener.source.line,
        ),
    )


__all__ = ["find_http3_alt_svc_review"]
