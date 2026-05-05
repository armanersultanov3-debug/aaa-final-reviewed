from __future__ import annotations

from fnmatch import fnmatchcase

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    TRANSPARENT_WRAPPER_BLOCKS,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._redirect_scope_utils import (
    has_whole_https_redirect,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_http_to_https_redirect"
TITLE = "Apache HTTP virtual host does not redirect to HTTPS"
TLS_PORTS = frozenset({443, 8443, 9443})
VHOST_TLS_DIRECTIVE_NAMES = frozenset(
    {
        "sslengine",
        "sslprotocol",
        "sslciphersuite",
        "sslcertificatefile",
        "sslcertificatekeyfile",
    }
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=(
        "A named Apache HTTP VirtualHost has a matching TLS VirtualHost but "
        "does not define an HTTP-to-HTTPS redirect."
    ),
    recommendation=(
        "Redirect the HTTP VirtualHost to HTTPS with Redirect, RedirectMatch, "
        "or a RewriteRule that issues an external HTTPS redirect."
    ),
    category="local",
    server_type="apache",
    order=360,
    tags=("tls",),
)
def find_missing_http_to_https_redirect(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    tls_hostnames = _tls_hostnames(config_ast)
    if not tls_hostnames:
        return []

    findings: list[Finding] = []
    for context in extract_virtualhost_contexts(config_ast):
        if context.optional_ancestor_names:
            continue
        hostnames = _context_hostnames(context)
        if not hostnames or not _hostnames_overlap(hostnames, tls_hostnames):
            continue
        if not _virtualhost_listens_on_http(context):
            continue
        if _has_https_redirect(context.node):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    f"Apache HTTP VirtualHost '{_context_label(context)}' has "
                    "a matching TLS VirtualHost but no HTTPS redirect."
                ),
                recommendation=(
                    "Add a permanent HTTPS redirect in the HTTP VirtualHost."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=context.node.source.file_path,
                    line=context.node.source.line,
                ),
            )
        )
    return findings


def _tls_hostnames(config_ast: ApacheConfigAst) -> set[str]:
    global_tls_ports = _global_tls_listen_ports(config_ast)
    hostnames: set[str] = set()
    for context in extract_virtualhost_contexts(config_ast):
        if context.optional_ancestor_names:
            continue
        if not _virtualhost_has_tls_intent(context, global_tls_ports):
            continue
        hostnames.update(_context_hostnames(context))
    return hostnames


def _hostnames_overlap(left: set[str], right: set[str]) -> bool:
    return any(
        _hostname_matches(lhs, rhs) or _hostname_matches(rhs, lhs)
        for lhs in left
        for rhs in right
    )


def _hostname_matches(hostname: str, pattern: str) -> bool:
    if "*" not in pattern and "?" not in pattern:
        return hostname == pattern
    return fnmatchcase(hostname, pattern)


def _context_hostnames(context: ApacheVirtualHostContext) -> set[str]:
    names = []
    if context.server_name:
        names.append(context.server_name)
    names.extend(context.server_aliases)
    return {name.lower() for name in names if name}


def _context_label(context: ApacheVirtualHostContext) -> str:
    return context.server_name or context.listen_address or "<unnamed>"


def _virtualhost_listens_on_http(context: ApacheVirtualHostContext) -> bool:
    return any(_address_port(address) == 80 for address in context.listen_addresses)


def _virtualhost_has_tls_intent(
    context: ApacheVirtualHostContext,
    global_tls_ports: frozenset[int],
) -> bool:
    directives = _iter_scoped_directives(context.node.children)
    if any(_is_sslengine_off(directive) for directive in directives):
        return False
    return _virtualhost_listens_on_tls(context, global_tls_ports) or any(
        _directive_has_vhost_tls_intent(directive) for directive in directives
    )


def _virtualhost_listens_on_tls(
    context: ApacheVirtualHostContext,
    global_tls_ports: frozenset[int],
) -> bool:
    return any(
        (port := _address_port(address)) is not None
        and (port in TLS_PORTS or port in global_tls_ports)
        for address in context.listen_addresses
    )


def _directive_has_vhost_tls_intent(directive: ApacheDirectiveNode) -> bool:
    name = directive.name.lower()
    if name not in VHOST_TLS_DIRECTIVE_NAMES:
        return False
    if _is_sslengine_off(directive):
        return False
    return True


def _is_sslengine_off(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "sslengine"
        and bool(directive.args)
        and directive.args[0].lower() == "off"
    )


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


def _iter_scoped_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
        elif node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
            directives.extend(_iter_scoped_directives(node.children))
    return directives


def _address_port(value: str) -> int | None:
    if value.isdigit():
        return int(value)
    if ":" not in value:
        return None
    _, _, port = value.rpartition(":")
    if not port.isdigit():
        return None
    return int(port)


def _has_https_redirect(block: ApacheBlockNode) -> bool:
    return has_whole_https_redirect(block)


__all__ = ["find_missing_http_to_https_redirect"]
