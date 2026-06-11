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
from webconf_audit.local.nginx.rules.header_utils import find_server_add_headers
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cis_nginx_v3_0_0

RULE_ID = "nginx.http3_alt_svc_review"


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
        {"add_header", "http3"},
    ):
        quic_listeners = [
            directive
            for directive in find_child_directives(server_block, "listen")
            if any(arg.lower() == "quic" for arg in directive.args)
        ]
        if not quic_listeners:
            continue

        findings.append(
            _build_finding(
                listener=quic_listeners[0],
                http3_state=_effective_http3_state(
                    server_block,
                    inherited_directives,
                ),
                alt_svc=_effective_alt_svc(
                    server_block,
                    inherited_directives,
                ),
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


def _effective_alt_svc(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> str | None:
    for directive in find_server_add_headers(server_block, inherited_directives):
        if not directive.args or directive.args[0].lower() != "alt-svc":
            continue
        value_args = directive.args[1:]
        if value_args and value_args[-1].lower() == "always":
            value_args = value_args[:-1]
        return _strip_matching_quotes(" ".join(value_args).strip())
    return None


def _strip_matching_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


def _build_finding(
    *,
    listener: DirectiveNode,
    http3_state: str,
    alt_svc: str | None,
) -> Finding:
    alt_svc_text = (
        f"effective Alt-Svc value: {alt_svc}"
        if alt_svc is not None
        else "effective Alt-Svc header is missing"
    )
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
