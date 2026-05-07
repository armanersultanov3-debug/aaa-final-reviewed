from __future__ import annotations

from webconf_audit.local.apache.effective import (
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    explicit_module_inventory,
    has_https_upstream_proxy,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ssl_proxy_peer_name_check_disabled"
TITLE = "Apache HTTPS upstream proxy disables peer name validation"
DESCRIPTION = (
    "Apache proxies requests to an HTTPS upstream with peer-name validation disabled."
)
RECOMMENDATION = (
    "Keep 'SSLProxyCheckPeerName On' and avoid disabling upstream hostname validation."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=369,
    tags=("tls", "proxy"),
)
def find_ssl_proxy_peer_name_check_disabled(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    modules = explicit_module_inventory(config_ast)
    findings: list[Finding] = []
    contexts = extract_virtualhost_contexts(config_ast)

    if has_https_upstream_proxy(config_ast.nodes, modules):
        effective = build_server_effective_config(config_ast)
        disabled_source = _disabled_peer_name_source(effective.directives)
        if disabled_source is not None:
            findings.append(_finding_from_source(disabled_source))

    if not contexts:
        return findings

    for context in contexts:
        if context.optional_ancestor_names:
            continue
        if not has_https_upstream_proxy(context.node.children, modules):
            continue

        effective = build_server_effective_config(config_ast, virtualhost_context=context)
        disabled_source = _disabled_peer_name_source(effective.directives)
        if disabled_source is None:
            continue

        findings.append(_finding_from_source(disabled_source))

    return findings


def _peer_name_check_explicitly_disabled(directives) -> bool:
    return _disabled_peer_name_source(directives) is not None


def _disabled_peer_name_source(directives):
    for name in ("sslproxycheckpeername", "sslproxycheckpeercn"):
        directive = directives.get(name)
        if directive is None or not directive.args:
            continue
        first_arg = directive.args[0]
        if isinstance(first_arg, list):
            continue
        if first_arg.lower() == "off":
            return directive.origin.source
    return None


def _finding_from_source(source) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="medium",
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path if source is not None else None,
            line=source.line if source is not None else None,
        ),
    )


__all__ = ["find_ssl_proxy_peer_name_check_disabled"]
