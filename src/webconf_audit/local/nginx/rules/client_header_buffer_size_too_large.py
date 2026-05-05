from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import (
    iter_last_direct_child_directives,
    parse_size_bytes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.client_header_buffer_size_too_large"
MAX_CLIENT_HEADER_BUFFER_SIZE_BYTES = 64 * 1024


@rule(
    rule_id=RULE_ID,
    title="client_header_buffer_size is unusually large",
    severity="low",
    description=(
        "Nginx sets 'client_header_buffer_size' above a conservative local "
        "hardening threshold."
    ),
    recommendation=(
        "Avoid large global request-header buffers unless an application endpoint "
        "requires them and the allocation impact is documented."
    ),
    category="local",
    server_type="nginx",
    order=247,
)
def find_client_header_buffer_size_too_large(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive, _parent in iter_last_direct_child_directives(
        config_ast,
        "client_header_buffer_size",
        block_names={"http", "server"},
    ):
        if not directive.args:
            continue
        size = parse_size_bytes(directive.args[0])
        if size is None or size <= MAX_CLIENT_HEADER_BUFFER_SIZE_BYTES:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="client_header_buffer_size is unusually large",
                severity="low",
                description=(
                    "Nginx sets 'client_header_buffer_size "
                    f"{directive.args[0]};', which is above 64 KB and can increase "
                    "per-connection memory pressure."
                ),
                recommendation=(
                    "Avoid large global request-header buffers unless an application "
                    "endpoint requires them and the allocation impact is documented."
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


__all__ = ["find_client_header_buffer_size_too_large"]
