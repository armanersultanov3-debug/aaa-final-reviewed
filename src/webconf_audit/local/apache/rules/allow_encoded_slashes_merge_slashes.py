"""Apache CVE-related AllowEncodedSlashes / MergeSlashes rule."""

from __future__ import annotations

from webconf_audit.local.apache.effective import (
    EffectiveDirective,
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.server_directive_utils import (
    deduplicate_findings_by_location,
    directive_location,
    virtualhost_label,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import StandardReference, rule

RULE_ID = "apache.allow_encoded_slashes_with_merge_slashes_off"
TITLE = "Apache encoded slashes are allowed while slash merging is disabled"
DESCRIPTION = (
    "Apache sets AllowEncodedSlashes On together with MergeSlashes Off. This "
    "CVE-2025-59775-related configuration pattern is version- and platform-"
    "dependent, but on affected Apache HTTP Server for Windows builds it can "
    "contribute to SSRF and NTLM hash leakage."
)
RECOMMENDATION = (
    "Avoid combining AllowEncodedSlashes On with MergeSlashes Off unless it is "
    "strictly required. Prefer MergeSlashes On, review URL normalization needs, "
    "and confirm the Apache HTTP Server version and platform patch level."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="high",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    tags=("cve", "url-normalization", "ssrf"),
    standards=(
        StandardReference(
            standard="CVE",
            reference="CVE-2025-59775",
            url="https://httpd.apache.org/security/vulnerabilities_24.html",
            coverage="related",
            note=(
                "Detects the risky directive combination; affected-version and "
                "Windows platform state are not proven by static config analysis."
            ),
        ),
    ),
    order=365,
)
def find_allow_encoded_slashes_with_merge_slashes_off(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    for scope, label in _iter_server_effective_scopes(config_ast):
        allow_encoded = scope.directives.get("allowencodedslashes")
        merge_slashes = scope.directives.get("mergeslashes")
        if _first_arg_lower(allow_encoded) != "on":
            continue
        if _first_arg_lower(merge_slashes) != "off":
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="high",
                description=f"{DESCRIPTION} Scope: {label}.",
                recommendation=RECOMMENDATION,
                location=directive_location(allow_encoded),
            )
        )
    return deduplicate_findings_by_location(findings)


def _iter_server_effective_scopes(config_ast: ApacheConfigAst):
    contexts = extract_virtualhost_contexts(config_ast)
    if not contexts:
        yield build_server_effective_config(config_ast), "global"
        return
    for context in contexts:
        yield (
            build_server_effective_config(config_ast, virtualhost_context=context),
            virtualhost_label(context),
        )


def _first_arg_lower(directive: EffectiveDirective | None) -> str | None:
    if directive is None or not directive.args:
        return None
    first = directive.args[0]
    if isinstance(first, list) or not first:
        return None
    return first.lower()


__all__ = ["find_allow_encoded_slashes_with_merge_slashes_off"]
