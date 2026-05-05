from __future__ import annotations

from dataclasses import dataclass

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    EffectiveDirective,
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
    ApacheSourceSpan,
)
from webconf_audit.models import Finding, SourceLocation

TLS_PORTS = frozenset({443, 8443, 9443})
TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)
TLS_DIRECTIVE_NAMES = frozenset(
    {
        "sslengine",
        "sslprotocol",
        "sslciphersuite",
        "sslcertificatefile",
        "sslcertificatekeyfile",
        "sslhonorcipherorder",
        "sslcompression",
        "sslinsecurerenegotiation",
        "sslusestapling",
        "sslstaplingcache",
        "sslstaplingreturnrespondererrors",
        "sslsessioncache",
        "sslsessioncachetimeout",
    }
)


@dataclass(frozen=True, slots=True)
class ApacheTLSScope:
    label: str
    directives: dict[str, EffectiveDirective]
    context: ApacheVirtualHostContext | None
    fallback_source: ApacheSourceSpan | None


def iter_tls_scopes(config_ast: ApacheConfigAst) -> list[ApacheTLSScope]:
    global_tls_ports = _global_tls_listen_ports(config_ast)
    contexts = extract_virtualhost_contexts(config_ast)
    if contexts:
        return [
            scope
            for context in contexts
            if (
                scope := _virtualhost_tls_scope(config_ast, context, global_tls_ports)
            )
            is not None
        ]

    effective = build_server_effective_config(config_ast)
    fallback_source = config_ast.nodes[0].source if config_ast.nodes else None
    if not _has_global_tls_intent(config_ast, effective.directives):
        return []
    return [
        ApacheTLSScope(
            label="global",
            directives=effective.directives,
            context=None,
            fallback_source=fallback_source,
        )
    ]


def directive_args(directive: EffectiveDirective | None) -> list[str]:
    if directive is None or not directive.args or isinstance(directive.args[0], list):
        return []
    return list(directive.args)


def first_arg_lower(directive: EffectiveDirective | None) -> str | None:
    args = directive_args(directive)
    if not args:
        return None
    return args[0].lower()


def directive_location(
    scope: ApacheTLSScope,
    directive: EffectiveDirective | None,
) -> SourceLocation | None:
    if directive is not None:
        source = directive.origin.source
    elif scope.context is not None:
        source = scope.context.node.source
    elif scope.fallback_source is not None:
        source = scope.fallback_source
    else:
        return None

    return SourceLocation(
        mode="local",
        kind="file",
        file_path=source.file_path,
        line=source.line,
    )


def make_tls_finding(
    scope: ApacheTLSScope,
    *,
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str,
    directive: EffectiveDirective | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        recommendation=recommendation,
        location=directive_location(scope, directive),
    )


def _virtualhost_tls_scope(
    config_ast: ApacheConfigAst,
    context: ApacheVirtualHostContext,
    global_tls_ports: frozenset[int],
) -> ApacheTLSScope | None:
    effective = build_server_effective_config(config_ast, virtualhost_context=context)
    if not (
        _virtualhost_listens_on_tls(context, global_tls_ports)
        or _has_tls_directive_intent(effective.directives)
    ):
        return None

    return ApacheTLSScope(
        label=context.server_name or context.listen_address or "<unnamed>",
        directives=effective.directives,
        context=context,
        fallback_source=context.node.source,
    )


def _has_global_tls_intent(
    config_ast: ApacheConfigAst,
    directives: dict[str, EffectiveDirective],
) -> bool:
    return _has_tls_directive_intent(directives) or _global_listens_on_tls(config_ast)


def _has_tls_directive_intent(directives: dict[str, EffectiveDirective]) -> bool:
    for name in TLS_DIRECTIVE_NAMES:
        directive = directives.get(name)
        if directive is None:
            continue
        if name == "sslengine" and first_arg_lower(directive) == "off":
            continue
        return True
    return False


def _virtualhost_listens_on_tls(
    context: ApacheVirtualHostContext,
    global_tls_ports: frozenset[int],
) -> bool:
    return any(
        _address_mentions_tls(address, tls_ports=global_tls_ports)
        for address in context.listen_addresses
    )


def _global_listens_on_tls(config_ast: ApacheConfigAst) -> bool:
    return bool(_global_tls_listen_ports(config_ast))


def _iter_top_level_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
        elif node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
            directives.extend(_iter_top_level_directives(node.children))
    return directives


def _listen_directive_mentions_tls(directive: ApacheDirectiveNode) -> bool:
    return _listen_directive_tls_port(directive) is not None


def _global_tls_listen_ports(config_ast: ApacheConfigAst) -> frozenset[int]:
    return frozenset(
        port
        for directive in _iter_top_level_directives(config_ast.nodes)
        if directive.name.lower() == "listen"
        if (port := _listen_directive_tls_port(directive)) is not None
    )


def _listen_directive_tls_port(directive: ApacheDirectiveNode) -> int | None:
    if not directive.args:
        return None

    port = _address_port(directive.args[0])
    if port is None:
        return None

    if any(arg.lower() == "https" for arg in directive.args[1:]):
        return port
    if port in TLS_PORTS:
        return port
    return None


def _address_mentions_tls(value: str, *, tls_ports: frozenset[int]) -> bool:
    port = _address_port(value)
    return port is not None and (port in TLS_PORTS or port in tls_ports)


def _address_port(value: str) -> int | None:
    if value.isdigit():
        return int(value)
    if ":" not in value:
        return None
    _, _, port = value.rpartition(":")
    if not port.isdigit():
        return None
    return int(port)


__all__ = [
    "ApacheTLSScope",
    "directive_args",
    "first_arg_lower",
    "iter_tls_scopes",
    "make_tls_finding",
]
