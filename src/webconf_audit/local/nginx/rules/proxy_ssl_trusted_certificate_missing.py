from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst
from webconf_audit.local.nginx.rules._proxy_tls_utils import (
    iter_https_proxy_scopes,
    proxy_ssl_verify_is_on,
    trusted_certificate_is_configured,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cwe, nist_sp

RULE_ID = "nginx.proxy_ssl_trusted_certificate_missing"
TITLE = "HTTPS upstream proxy verification lacks a trusted certificate bundle"
DESCRIPTION = (
    "Scope enables 'proxy_ssl_verify on' for an HTTPS upstream without "
    "'proxy_ssl_trusted_certificate'."
)
RECOMMENDATION = (
    "Set 'proxy_ssl_trusted_certificate' to the CA bundle or trust anchor used "
    "to validate this HTTPS upstream."
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
    ),
    order=271,
    tags=("tls", "proxy"),
)
def find_proxy_ssl_trusted_certificate_missing(
    config_ast: ConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []

    for scope in iter_https_proxy_scopes(config_ast):
        if not proxy_ssl_verify_is_on(scope.proxy_ssl_verify_directives):
            continue
        if trusted_certificate_is_configured(scope.trusted_certificate_directives):
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


__all__ = ["find_proxy_ssl_trusted_certificate_missing"]
