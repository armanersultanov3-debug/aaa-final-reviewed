"""Apache CVE-related ProxyPreserveHost / HTTP/2 backend rule."""

from __future__ import annotations

from collections.abc import Iterable

from webconf_audit.local.apache.effective import (
    EffectiveDirective,
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules.server_directive_utils import (
    deduplicate_findings_by_location,
    virtualhost_label,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule

RULE_ID = "apache.proxy_http2_backend_with_preserve_host"
TITLE = "Apache HTTP/2 backend proxy preserves the client Host header"
DESCRIPTION = (
    "Apache combines ProxyPreserveHost On with an HTTP/2 or h2c ProxyPass "
    "backend. This CVE-2025-49630-related configuration pattern depends on "
    "Apache version and backend topology, but it is risky enough to review "
    "because Host preservation can affect reverse-proxy routing semantics."
)
RECOMMENDATION = (
    "Confirm that ProxyPreserveHost On is required for the affected reverse "
    "proxy route, review h2/h2c backend handling, and verify the Apache HTTP "
    "Server version is patched for CVE-2025-49630."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    tags=("cve", "proxy", "http2"),
    standards=(
        StandardReference(
            standard="CVE",
            reference="CVE-2025-49630",
            url="https://httpd.apache.org/security/vulnerabilities_24.html",
            coverage="related",
            note=(
                "Detects the directive topology; affected-version and backend "
                "runtime behaviour are not proven by static config analysis."
            ),
        ),
    ),
    order=366,
)
def find_proxy_http2_backend_with_preserve_host(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []

    if _preserve_host_enabled(
        build_server_effective_config(config_ast).directives.get("proxypreservehost")
    ):
        findings.extend(
            _find_h2_proxypass(
                _global_scope_nodes(config_ast.nodes),
                scope_label="global",
            )
        )

    contexts = extract_virtualhost_contexts(config_ast)
    for context in contexts:
        effective = build_server_effective_config(
            config_ast,
            virtualhost_context=context,
        )
        if not _preserve_host_enabled(effective.directives.get("proxypreservehost")):
            continue
        findings.extend(
            _find_h2_proxypass(
                context.node.children,
                scope_label=virtualhost_label(context),
            )
        )

    return deduplicate_findings_by_location(findings)


def _global_scope_nodes(
    nodes: Iterable[ApacheDirectiveNode | ApacheBlockNode],
) -> Iterable[ApacheDirectiveNode | ApacheBlockNode]:
    for node in nodes:
        if isinstance(node, ApacheBlockNode) and node.name.lower() == "virtualhost":
            continue
        yield node


def _preserve_host_enabled(directive: EffectiveDirective | None) -> bool:
    if directive is None or not directive.args:
        return False
    first = directive.args[0]
    return not isinstance(first, list) and first.lower() == "on"


def _find_h2_proxypass(
    nodes: Iterable[ApacheDirectiveNode | ApacheBlockNode],
    *,
    scope_label: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for directive in _iter_directives(nodes):
        if directive.name.lower() != "proxypass":
            continue
        backend = _h2_backend_argument(directive.args)
        if backend is None:
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="medium",
                description=(
                    f"{DESCRIPTION} Scope: {scope_label}; backend: {backend}."
                ),
                recommendation=RECOMMENDATION,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )
    return findings


def _iter_directives(
    nodes: Iterable[ApacheDirectiveNode | ApacheBlockNode],
) -> Iterable[ApacheDirectiveNode]:
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            yield node
        else:
            yield from _iter_directives(node.children)


def _h2_backend_argument(args: list[str]) -> str | None:
    for arg in args:
        normalized = arg.strip('"').strip("'").lower()
        if normalized.startswith(("h2://", "h2c://")):
            return arg
    return None


__all__ = ["find_proxy_http2_backend_with_preserve_host"]
