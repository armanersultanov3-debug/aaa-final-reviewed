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

RULE_ID = "apache.ssl_proxy_verify_not_required"
TITLE = "Apache HTTPS upstream proxy does not require certificate verification"
DESCRIPTION = (
    "Apache proxies requests to an HTTPS upstream without 'SSLProxyVerify require'."
)
RECOMMENDATION = (
    "Enable upstream TLS certificate verification with 'SSLProxyEngine On' and "
    "'SSLProxyVerify require' for HTTPS proxy targets."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=368,
    tags=("tls", "proxy"),
)
def find_ssl_proxy_verify_not_required(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    modules = explicit_module_inventory(config_ast)
    findings: list[Finding] = []
    contexts = extract_virtualhost_contexts(config_ast)

    if has_https_upstream_proxy(config_ast.nodes, modules):
        effective = build_server_effective_config(config_ast)
        if not _verify_is_required(effective.directives):
            findings.append(_finding_from_source(config_ast.nodes[0].source if config_ast.nodes else None))

    if not contexts:
        return findings

    for context in contexts:
        if context.optional_ancestor_names:
            continue
        if not has_https_upstream_proxy(context.node.children, modules):
            continue

        effective = build_server_effective_config(config_ast, virtualhost_context=context)
        if _verify_is_required(effective.directives):
            continue

        findings.append(_finding_from_source(context.node.source))

    return findings


def _verify_is_required(directives) -> bool:
    directive = directives.get("sslproxyverify")
    if directive is None or not directive.args:
        return False
    first_arg = directive.args[0]
    if isinstance(first_arg, list):
        return False
    return first_arg.lower() == "require"


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


__all__ = ["find_ssl_proxy_verify_not_required"]
