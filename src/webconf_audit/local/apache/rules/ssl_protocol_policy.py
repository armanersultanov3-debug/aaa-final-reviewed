"""apache.ssl_protocol_missing_or_weak -- Apache explicitly enables legacy TLS versions."""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._tls_policy_utils import (
    ApacheTLSScope,
    directive_args,
    iter_tls_scopes,
    make_tls_finding,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021, rfc

RULE_ID = "apache.ssl_protocol_missing_or_weak"
LEGACY_RULE_ID = "apache.tls_legacy_versions_explicitly_enabled"
TITLE = "Apache TLS protocol policy is missing or weak"
_DEFAULT_ALL_WEAK = frozenset({"SSLv3", "TLSv1", "TLSv1.1"})
_WEAK_ALIASES = {
    "sslv2": "SSLv2",
    "sslv3": "SSLv3",
    "tlsv1": "TLSv1",
    "tlsv1.0": "TLSv1",
    "tlsv1.1": "TLSv1.1",
}


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=(
        "A TLS-enabled Apache scope does not define SSLProtocol, or it allows "
        "legacy SSL/TLS protocol versions."
    ),
    recommendation=(
        "Configure SSLProtocol to allow only TLSv1.2 and TLSv1.3, for example "
        "'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'."
    ),
    category="local",
    server_type="apache",
    standards=(
        cwe(327),
        owasp_top10_2021("A02:2021"),
        asvs_5("12.1.1", coverage="partial", note="Missing policy and legacy-version checks."),
    ),
    order=349,
    tags=("tls",),
)
def find_ssl_protocol_policy(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        directive = scope.directives.get("sslprotocol")
        if directive is None or not directive_args(directive):
            findings.append(_missing_finding(scope))
            continue

        weak = _enabled_weak_protocols(directive_args(directive))
        if weak:
            findings.append(
                make_tls_finding(
                    scope,
                    rule_id=RULE_ID,
                    title=TITLE,
                    severity="medium",
                    description=(
                        f"TLS scope '{scope.label}' enables weak protocols: "
                        + ", ".join(weak)
                    ),
                    recommendation=(
                        "Disable SSLv2, SSLv3, TLSv1, and TLSv1.1. Use TLSv1.2+."
                    ),
                    directive=directive,
                )
            )
    return findings


@rule(
    rule_id=LEGACY_RULE_ID,
    title="Apache explicitly enables legacy TLS versions",
    severity="medium",
    description="Apache explicitly enables legacy TLS protocol versions.",
    recommendation=(
        "Remove SSLv3, TLSv1, and TLSv1.1 from SSLProtocol and require "
        "TLSv1.2 or TLSv1.3 only."
    ),
    category="local",
    server_type="apache",
    standards=(
        cwe(327),
        owasp_top10_2021("A02:2021"),
        asvs_5("12.1.1"),
        rfc(
            8996,
            coverage="partial",
            note="Directly covers TLS 1.0 / 1.1 deprecation and also flags adjacent SSLv3 enablement.",
        ),
    ),
    order=349,
    tags=("tls",),
)
def find_tls_legacy_versions_explicitly_enabled(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_tls_scopes(config_ast):
        directive = scope.directives.get("sslprotocol")
        if directive is None or not directive_args(directive):
            continue

        legacy = _enabled_weak_protocols(directive_args(directive))
        if not legacy:
            continue

        findings.append(
            make_tls_finding(
                scope,
                rule_id=LEGACY_RULE_ID,
                title="Apache explicitly enables legacy TLS versions",
                severity="medium",
                description=(
                    f"TLS scope '{scope.label}' explicitly enables legacy "
                    f"protocol versions: {', '.join(legacy)}."
                ),
                recommendation=(
                    "Remove SSLv3, TLSv1, and TLSv1.1 from SSLProtocol and "
                    "require TLSv1.2 or TLSv1.3 only."
                ),
                directive=directive,
            )
        )
    return findings


def _missing_finding(scope: ApacheTLSScope) -> Finding:
    return make_tls_finding(
        scope,
        rule_id=RULE_ID,
        title=TITLE,
        severity="medium",
        description=(
            f"TLS scope '{scope.label}' does not define an effective "
            "SSLProtocol policy."
        ),
        recommendation="Set SSLProtocol to an explicit TLSv1.2+ policy.",
    )


def _enabled_weak_protocols(args: list[str]) -> list[str]:
    explicit_enabled: set[str] = set()
    disabled: set[str] = set()
    all_mode = False

    for raw in args:
        token = raw.strip()
        if not token:
            continue
        action = token[0] if token[0] in "+-" else ""
        name = token[1:] if action else token
        lowered_name = name.lower()

        if lowered_name == "all":
            all_mode = action != "-"
            if action == "-":
                explicit_enabled.clear()
                disabled.update(_DEFAULT_ALL_WEAK)
            continue

        weak = _WEAK_ALIASES.get(lowered_name)
        if weak is None:
            continue
        if action == "-":
            disabled.add(weak)
            explicit_enabled.discard(weak)
        else:
            explicit_enabled.add(weak)
            disabled.discard(weak)

    weak_protocols = set(explicit_enabled)
    if all_mode:
        weak_protocols.update(_DEFAULT_ALL_WEAK - disabled)
    return sorted(weak_protocols)


__all__ = [
    "find_ssl_protocol_policy",
    "find_tls_legacy_versions_explicitly_enabled",
]
