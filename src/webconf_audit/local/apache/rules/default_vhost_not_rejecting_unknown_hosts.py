"""Implements rule ``apache.default_vhost_not_rejecting_unknown_hosts``.

Location: ``src/webconf_audit/local/apache/rules/default_vhost_not_rejecting_unknown_hosts.py``.
"""

from __future__ import annotations

from collections import defaultdict

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    explicit_module_inventory,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._redirect_scope_utils import (
    is_redirect_only_virtualhost,
)
from webconf_audit.local.apache.rules._tls_policy_utils import (
    TLS_DIRECTIVE_NAMES,
    TLS_PORTS,
    TRANSPARENT_WRAPPER_BLOCKS,
    _global_tls_listen_ports,
)
from webconf_audit.local.apache.rules._vhost_rejection_utils import (
    listen_keys,
    rejects_unknown_hosts,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule
from webconf_audit.standards import owasp_top10_2021

RULE_ID = "apache.default_vhost_not_rejecting_unknown_hosts"
TITLE = "Apache default virtual host does not reject unknown hosts"
DESCRIPTION = (
    "The first non-TLS Apache VirtualHost for a listen address acts as the "
    "default host, but it does not explicitly reject requests for unknown host "
    "names."
)
RECOMMENDATION = (
    "Use a dedicated first/default VirtualHost for the listen address that "
    "rejects unknown hosts with 'Require all denied', a catch-all forbidden "
    "rewrite, or a whole-scope HTTP-to-HTTPS redirect."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    standards=(
        owasp_top10_2021("A05:2021"),
        StandardReference(
            standard="CIS",
            reference="Apache HTTP Server 2.4 v2.3.0 sections 5.14/5.15",
            url="https://www.cisecurity.org/benchmark/apache_http_server",
            coverage="partial",
            note=(
                "First/default non-TLS VirtualHost catch-all rejection only."
            ),
        ),
    ),
    order=367,
    tags=("host",),
)
def find_default_vhost_not_rejecting_unknown_hosts(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    seen_contexts: set[int] = set()
    modules = explicit_module_inventory(config_ast)

    for contexts in _non_tls_contexts_by_listen_key(config_ast).values():
        shared_listen_address = len(contexts) > 1
        context = contexts[0]
        context_id = id(context)
        if context_id in seen_contexts:
            continue
        seen_contexts.add(context_id)

        if rejects_unknown_hosts(context.node, modules) or is_redirect_only_virtualhost(
            context,
            modules,
        ):
            continue
        findings.append(
            _finding(context, shared_listen_address=shared_listen_address)
        )

    return findings


def _non_tls_contexts_by_listen_key(
    config_ast: ApacheConfigAst,
) -> dict[str, list[ApacheVirtualHostContext]]:
    contexts = extract_virtualhost_contexts(config_ast)
    global_tls_ports = _global_tls_listen_ports(config_ast)
    contexts_by_key: dict[str, list[ApacheVirtualHostContext]] = defaultdict(list)

    for context in contexts:
        if context.optional_ancestor_names:
            continue
        for listen_key in listen_keys(context):
            if _is_tls_listen_key(
                listen_key,
                context,
                global_tls_ports=global_tls_ports,
            ):
                continue
            contexts_by_key[listen_key].append(context)

    return dict(contexts_by_key)


def _is_tls_listen_key(
    listen_key: str,
    context: ApacheVirtualHostContext,
    *,
    global_tls_ports: frozenset[int],
) -> bool:
    if _has_virtualhost_tls_directive_intent(context.node.children):
        return True
    port = _listen_key_port(listen_key)
    return port is not None and (port in TLS_PORTS or port in global_tls_ports)


def _listen_key_port(listen_key: str) -> int | None:
    _, _, port = listen_key.rpartition(":")
    if not port.isdigit():
        return None
    return int(port)


def _has_virtualhost_tls_directive_intent(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> bool:
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
                if _has_virtualhost_tls_directive_intent(node.children):
                    return True
            continue

        name = node.name.lower()
        if name not in TLS_DIRECTIVE_NAMES:
            continue
        if name == "sslengine" and _first_arg_lower(node) == "off":
            continue
        return True
    return False


def _first_arg_lower(directive: ApacheDirectiveNode) -> str | None:
    if not directive.args:
        return None
    return directive.args[0].lower()


def _finding(
    context: ApacheVirtualHostContext, *, shared_listen_address: bool
) -> Finding:
    source = context.node.source
    label = context.server_name or context.listen_address or "<unnamed>"
    shared_suffix = (
        " on a shared non-TLS listen address" if shared_listen_address else ""
    )
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="low",
        description=(
            f"Apache default VirtualHost '{label}' can serve requests for "
            f"unknown host names{shared_suffix}."
        ),
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        ),
    )


__all__ = ["find_default_vhost_not_rejecting_unknown_hosts"]
