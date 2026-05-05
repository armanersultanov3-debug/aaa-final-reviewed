from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._tls_policy_utils import iter_tls_scopes
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
TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)
WHOLE_PATHS = frozenset({"", "/"})
WHOLE_PATTERNS = frozenset(
    {
        "^",
        "^/",
        "^/(.*)$",
        "^/(.*)",
        "^.*$",
        "^(.*)$",
        "^(.*)",
        ".*",
    }
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

    for context in _default_tls_contexts_by_listen_key(config_ast).values():
        context_id = id(context)
        if context_id in seen_contexts:
            continue
        seen_contexts.add(context_id)
        if _rejects_unknown_hosts(context.node):
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
        for listen_key in _listen_keys(context):
            defaults.setdefault(listen_key, context)
    return defaults


def _listen_keys(context: ApacheVirtualHostContext) -> list[str]:
    addresses = context.listen_addresses
    if not addresses and context.listen_address is not None:
        addresses = (context.listen_address,)
    return [_normalize_listen_key(address) for address in addresses]


def _normalize_listen_key(value: str) -> str:
    value = value.strip()
    if value.isdigit():
        return f"*:{value}"
    if value.startswith("[") and "]" in value:
        host, _, remainder = value[1:].partition("]")
        port = remainder[1:] if remainder.startswith(":") else ""
        return f"{_normalize_host(host)}:{port}" if port else _normalize_host(host)
    if ":" not in value:
        return value.lower()
    host, _, port = value.rpartition(":")
    if not port.isdigit():
        return value.lower()
    return f"{_normalize_host(host)}:{port}"


def _normalize_host(value: str) -> str:
    normalized = value.strip().strip("[]").lower()
    if normalized in {"", "*", "_default_"}:
        return "*"
    return normalized


def _rejects_unknown_hosts(block: ApacheBlockNode) -> bool:
    return _has_whole_scope_require_all_denied(block) or _has_forbidden_rewrite(block)


def _has_whole_scope_require_all_denied(block: ApacheBlockNode) -> bool:
    for node in block.children:
        if isinstance(node, ApacheDirectiveNode):
            continue
        name = node.name.lower()
        if name in TRANSPARENT_WRAPPER_BLOCKS:
            if _has_whole_scope_require_all_denied(node):
                return True
        elif _is_whole_request_scope(node) and _has_require_all_denied(node):
            return True
    return False


def _has_require_all_denied(block: ApacheBlockNode) -> bool:
    for node in block.children:
        if isinstance(node, ApacheDirectiveNode):
            if _is_require_all_denied(node):
                return True
            continue
        if node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
            if _has_require_all_denied(node):
                return True
    return False


def _is_require_all_denied(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "require"
        and len(directive.args) >= 2
        and directive.args[0].lower() == "all"
        and directive.args[1].lower() == "denied"
    )


def _is_whole_request_scope(block: ApacheBlockNode) -> bool:
    if not block.args:
        return False
    name = block.name.lower()
    value = block.args[0].strip().strip('"').strip("'")
    if name == "location":
        return value in WHOLE_PATHS
    if name == "locationmatch":
        return value in WHOLE_PATTERNS
    return False


def _has_forbidden_rewrite(
    block: ApacheBlockNode, *, rewrite_engine_enabled: bool = False
) -> bool:
    for node in block.children:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() in TRANSPARENT_WRAPPER_BLOCKS:
                if _has_forbidden_rewrite(
                    node,
                    rewrite_engine_enabled=rewrite_engine_enabled,
                ):
                    return True
            continue

        if node.name.lower() == "rewriteengine" and node.args:
            rewrite_engine_enabled = (
                node.args[0].strip().strip('"').strip("'").lower() == "on"
            )
            continue
        if rewrite_engine_enabled and _is_forbidden_rewrite_rule(node):
            return True
    return False


def _is_forbidden_rewrite_rule(directive: ApacheDirectiveNode) -> bool:
    return (
        directive.name.lower() == "rewriterule"
        and len(directive.args) >= 3
        and _is_whole_pattern(directive.args[0])
        and directive.args[1] == "-"
        and _rewrite_rule_rejects(directive.args[2:])
    )


def _is_whole_pattern(value: str) -> bool:
    return value.strip().strip('"').strip("'") in WHOLE_PATTERNS


def _rewrite_rule_rejects(args: list[str]) -> bool:
    for arg in args:
        normalized = arg.strip().strip("[]").lower()
        flags = [part.strip() for part in normalized.split(",")]
        if any(
            flag in {"f", "forbidden", "g", "gone"}
            or flag in {"r=400", "redirect=400", "r=403", "redirect=403"}
            or flag in {"r=404", "redirect=404"}
            for flag in flags
        ):
            return True
    return False


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
