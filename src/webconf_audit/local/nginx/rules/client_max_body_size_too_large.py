from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import (
    iter_last_direct_child_directives,
    parse_size_bytes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.client_max_body_size_too_large"
MAX_CLIENT_MAX_BODY_SIZE_BYTES = 100 * 1024 * 1024


@rule(
    rule_id=RULE_ID,
    title="client_max_body_size is unusually large",
    severity="low",
    description=(
        "Nginx sets 'client_max_body_size' above the conservative local "
        "hardening threshold."
    ),
    recommendation=(
        "Set 'client_max_body_size' to the smallest application-specific upload "
        "limit, and scope larger values only to upload endpoints."
    ),
    category="local",
    server_type="nginx",
    order=245,
)
def find_client_max_body_size_too_large(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive, _parent in iter_last_direct_child_directives(
        config_ast,
        "client_max_body_size",
        block_names={"http", "server", "location"},
    ):
        if not directive.args:
            continue
        size = parse_size_bytes(directive.args[0])
        if size is None or size <= MAX_CLIENT_MAX_BODY_SIZE_BYTES:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="client_max_body_size is unusually large",
                severity="low",
                description=(
                    "Nginx sets 'client_max_body_size "
                    f"{directive.args[0]};', which is above 100 MB and may allow "
                    "large request bodies to consume excessive resources."
                ),
                recommendation=(
                    "Set 'client_max_body_size' to the smallest application-specific "
                    "upload limit, and scope larger values only to upload endpoints."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


__all__ = ["find_client_max_body_size_too_large"]
