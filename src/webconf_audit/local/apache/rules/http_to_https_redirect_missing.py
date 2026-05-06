from __future__ import annotations

from functools import cache
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
        _hostnames_pair_overlap(lhs, rhs)
        for lhs in left
        for rhs in right
    )


def _hostnames_pair_overlap(left: str, right: str) -> bool:
    if _hostname_matches(left, right) or _hostname_matches(right, left):
        return True
    if _has_hostname_glob(left) and _has_hostname_glob(right):
        return _hostname_globs_overlap(left, right)
    return False


def _hostname_matches(hostname: str, pattern: str) -> bool:
    if not _has_hostname_glob(pattern):
        return hostname == pattern
    return fnmatchcase(hostname, pattern)


def _hostname_globs_overlap(left: str, right: str) -> bool:
    candidates = [_materialize_hostname_glob(left), _materialize_hostname_glob(right)]
    left_labels = left.split(".")
    right_labels = right.split(".")

    if len(left_labels) == len(right_labels):
        if all(
            _labels_globs_overlap(left_label, right_label)
            for left_label, right_label in zip(
                left_labels,
                right_labels,
                strict=True,
            )
        ):
            return True

    return any(
        _hostname_matches(candidate, left) and _hostname_matches(candidate, right)
        for candidate in candidates
    )


def _labels_globs_overlap(left: str, right: str) -> bool:
    @cache
    def overlaps(left_index: int, right_index: int) -> bool:
        if left_index == len(left) and right_index == len(right):
            return True

        left_char = left[left_index] if left_index < len(left) else None
        right_char = right[right_index] if right_index < len(right) else None

        if left_char == "*":
            if right_char == "*":
                return (
                    overlaps(left_index + 1, right_index)
                    or overlaps(left_index, right_index + 1)
                    or overlaps(left_index + 1, right_index + 1)
                )
            return overlaps(left_index + 1, right_index) or (
                right_char is not None and overlaps(left_index, right_index + 1)
            )

        if right_char == "*":
            return overlaps(left_index, right_index + 1) or (
                left_char is not None and overlaps(left_index + 1, right_index)
            )

        if left_char is None or right_char is None:
            return False

        if left_char == "?" or right_char == "?" or left_char == right_char:
            return overlaps(left_index + 1, right_index + 1)

        return False

    return overlaps(0, 0)


def _overlap_label_candidate(left: str, right: str) -> str | None:
    left_has_glob = _has_hostname_glob(left)
    right_has_glob = _has_hostname_glob(right)

    if not left_has_glob and not right_has_glob:
        return left if left == right else None
    if not left_has_glob:
        return left if fnmatchcase(left, right) else None
    if not right_has_glob:
        return right if fnmatchcase(right, left) else None

    for candidate in _label_overlap_candidates(left, right):
        if fnmatchcase(candidate, left) and fnmatchcase(candidate, right):
            return candidate
    return None


def _label_overlap_candidates(left: str, right: str) -> list[str]:
    left_chunks = _literal_chunks(left)
    right_chunks = _literal_chunks(right)
    candidates = [
        _materialize_label_glob(left),
        _materialize_label_glob(right),
        "x",
        *left_chunks,
        *right_chunks,
    ]

    for left_chunk in left_chunks or [""]:
        for right_chunk in right_chunks or [""]:
            candidates.extend(
                [
                    left_chunk + right_chunk,
                    right_chunk + left_chunk,
                    left_chunk + "x" + right_chunk,
                    right_chunk + "x" + left_chunk,
                ]
            )

    return [candidate for candidate in candidates if candidate]


def _materialize_hostname_glob(pattern: str) -> str:
    return ".".join(_materialize_label_glob(label) for label in pattern.split("."))


def _materialize_label_glob(pattern: str) -> str:
    materialized = "".join("x" if char in "*?" else char for char in pattern)
    return materialized or "x"


def _literal_chunks(pattern: str) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    for char in pattern:
        if char in "*?":
            if current:
                chunks.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        chunks.append("".join(current))
    return chunks


def _has_hostname_glob(value: str) -> bool:
    return "*" in value or "?" in value


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
