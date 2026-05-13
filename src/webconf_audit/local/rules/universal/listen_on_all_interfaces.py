"""universal.listen_on_all_interfaces

Informational finding when a listen point binds to wildcard IPv4 or IPv6
interfaces.
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "universal.listen_on_all_interfaces"

_WILDCARD_ADDRESS_KINDS = frozenset({"wildcard_ipv4", "wildcard_ipv6"})


@rule(
    rule_id=RULE_ID,
    title="Listening on all network interfaces",
    severity="info",
    description="A listen point binds to all interfaces (0.0.0.0, *, ::, [::], or implicit wildcard).",
    recommendation="If this service is internal, bind to a specific interface (e.g. 127.0.0.1) instead of all interfaces.",
    category="universal",
    input_kind="normalized",
    tags=("network",),
    order=111,
)
def check(config: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []
    seen_listens: set[tuple[int, str, str | None, str, int | None, str | None]] = set()

    for scope in config.scopes:
        for lp in scope.listen_points:
            if lp.address_kind not in _WILDCARD_ADDRESS_KINDS:
                continue

            addr = lp.address or ""
            src = lp.source
            listen_key = (
                lp.port,
                addr,
                scope.scope_name,
                src.file_path,
                src.line,
                src.xml_path,
            )
            if listen_key in seen_listens:
                continue
            seen_listens.add(listen_key)

            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Listening on all network interfaces",
                    severity="info",
                    description=(
                        f"Port {lp.port} is bound to all interfaces "
                        f"({addr or 'implicit wildcard'}). This is expected for "
                        "public-facing servers but may be a concern for internal services."
                    ),
                    recommendation=(
                        "If this service is internal, bind to a specific interface "
                        "(e.g. 127.0.0.1) instead of all interfaces."
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="xml" if src.xml_path else "file",
                        file_path=src.file_path,
                        line=src.line,
                        xml_path=src.xml_path,
                        details=f"server_type={config.server_type}",
                    ),
                    metadata={
                        "scope_name": scope.scope_name,
                        "address": addr or None,
                        "address_kind": lp.address_kind,
                        "port": lp.port,
                    },
                )
            )
    return findings
