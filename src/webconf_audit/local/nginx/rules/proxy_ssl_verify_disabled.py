from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst
from webconf_audit.local.nginx.rules._proxy_tls_utils import (
    iter_https_proxy_scopes,
    proxy_ssl_verify_is_on,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, nist_sp

RULE_ID = "nginx.proxy_ssl_verify_disabled"
TITLE = "HTTPS upstream proxy does not enable certificate verification"
DESCRIPTION = (
    "Scope proxies requests to an HTTPS upstream without effective "
    "'proxy_ssl_verify on'."
)
RECOMMENDATION = (
    "Set 'proxy_ssl_verify on;' for HTTPS upstreams and keep trust material "
    "configured with 'proxy_ssl_trusted_certificate'."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    standards=(
        nist_sp("800-53 Rev. 5", "AC-4"),
        cwe(295),
        asvs_5("12.2.2"),
    ),
    order=270,
    tags=("tls", "proxy"),
)
def find_proxy_ssl_verify_disabled(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for scope in iter_https_proxy_scopes(config_ast):
        if proxy_ssl_verify_is_on(scope.proxy_ssl_verify_directives):
            continue
        findings.append(_finding(scope.block))

    return findings


def _finding(block: BlockNode) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title=TITLE,
        severity="medium",
        description=DESCRIPTION,
        recommendation=RECOMMENDATION,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=block.source.file_path,
            line=block.source.line,
        ),
    )


__all__ = ["find_proxy_ssl_verify_disabled"]
