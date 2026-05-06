from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
)
from webconf_audit.local.apache.rules._redirect_scope_utils import (
    has_whole_https_redirect,
)
from webconf_audit.local.apache.rules._tls_policy_utils import ApacheTLSScope, iter_tls_scopes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_http_to_https_redirect"
TITLE = "Apache HTTP virtual host does not redirect to HTTPS"


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
    tls_scopes = _tls_scopes(config_ast)
    if not tls_scopes:
        return []

    findings: list[Finding] = []
    for context in extract_virtualhost_contexts(config_ast):
        if context.optional_ancestor_names:
            continue
        hostnames = _context_hostnames(context)
        if not hostnames or not _has_matching_tls_scope(context, tls_scopes):
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


def _tls_scopes(config_ast: ApacheConfigAst) -> list[ApacheTLSScope]:
    scopes: list[ApacheTLSScope] = []
    for scope in iter_tls_scopes(config_ast):
        if scope.context is None:
            continue
        if scope.context.optional_ancestor_names:
            continue
        scopes.append(scope)
    return scopes


def _has_matching_tls_scope(
    context: ApacheVirtualHostContext,
    tls_scopes: list[ApacheTLSScope],
) -> bool:
    hostnames = _context_hostnames(context)
    for scope in tls_scopes:
        tls_context = scope.context
        if tls_context is None:
            continue

        tls_hostnames = _context_hostnames(tls_context)
        if tls_hostnames and not hostnames.isdisjoint(tls_hostnames):
            return True
        if not tls_hostnames and _listen_addresses_overlap(context, tls_context):
            return True
    return False


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


def _listen_addresses_overlap(
    left: ApacheVirtualHostContext,
    right: ApacheVirtualHostContext,
) -> bool:
    return any(
        _address_hosts_overlap(left_address, right_address)
        for left_address in left.listen_addresses
        for right_address in right.listen_addresses
    )


def _address_hosts_overlap(left: str, right: str) -> bool:
    left_host = _address_host(left)
    right_host = _address_host(right)
    return "*" in {left_host, right_host} or left_host == right_host


def _address_host(value: str) -> str:
    if value.isdigit():
        return "*"
    if ":" not in value:
        return value.lower()
    host, _, port = value.rpartition(":")
    if not port.isdigit():
        return value.lower()
    return host.lower() or "*"


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
