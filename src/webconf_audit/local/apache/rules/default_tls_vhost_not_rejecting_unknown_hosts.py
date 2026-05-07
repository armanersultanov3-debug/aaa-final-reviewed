from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    explicit_module_inventory,
)
from webconf_audit.local.apache.rules._tls_policy_utils import iter_tls_scopes
from webconf_audit.local.apache.rules._vhost_rejection_utils import (
    listen_keys,
    rejects_unknown_hosts,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule
from webconf_audit.standards import owasp_top10_2021

RULE_ID = "apache.default_tls_vhost_not_rejecting_unknown_hosts"
TITLE = "Apache default TLS virtual host does not reject unknown hosts"
DESCRIPTION = (
    "The first TLS VirtualHost for an address acts as the default host, but it "
    "does not explicitly reject requests for unknown host names."
)
RECOMMENDATION = (
    "Use a dedicated default TLS VirtualHost that rejects unknown hosts with "
    "'Require all denied' on the whole URL space or a catch-all forbidden rewrite."
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
            reference="Apache HTTP Server 2.4 v2.3.0 §5.14",
            url="https://www.cisecurity.org/benchmark/apache_http_server",
            coverage="partial",
            note="First/default TLS VirtualHost catch-all rejection only.",
        ),
    ),
    order=366,
    tags=("tls",),
)
def find_default_tls_vhost_not_rejecting_unknown_hosts(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    seen_contexts: set[int] = set()
    modules = explicit_module_inventory(config_ast)

    for context in _default_tls_contexts_by_listen_key(config_ast).values():
        context_id = id(context)
        if context_id in seen_contexts:
            continue
        seen_contexts.add(context_id)
        if rejects_unknown_hosts(context.node, modules):
            continue
        findings.append(_finding(context))

    return findings


def _default_tls_contexts_by_listen_key(
    config_ast: ApacheConfigAst,
) -> dict[str, ApacheVirtualHostContext]:
    defaults: dict[str, ApacheVirtualHostContext] = {}
    for scope in iter_tls_scopes(config_ast):
        context = scope.context
        if context is None or context.optional_ancestor_names:
            continue
        for listen_key in listen_keys(context):
            defaults.setdefault(listen_key, context)
    return defaults


def _finding(context: ApacheVirtualHostContext) -> Finding:
    source = context.node.source
    label = context.server_name or context.listen_address or "<unnamed>"
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="low",
        description=(
            f"Apache default TLS VirtualHost '{label}' can serve requests for "
            "unknown host names."
        ),
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        ),
    )


__all__ = ["find_default_tls_vhost_not_rejecting_unknown_hosts"]
